//! Detects leaks of a planted value's random tail without its marker.
//!
//! The registry never stores values, so each tail is stored as truncated
//! SHA-256 hashes of every `WINDOW`-character window. Recovering a window
//! from its hash means searching at least 62^16 candidates.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Characters a tail can contain (base62 plus the base64 extras).
fn is_tail_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

pub const WINDOW: usize = 16;

type Key = [u8; 16];

fn key(window: &[u8]) -> Key {
    let digest = Sha256::new()
        .chain_update(b"agent-tripwire-tail:")
        .chain_update(window)
        .finalize();
    digest[..16].try_into().expect("digest is 32 bytes")
}

/// Hex hashes of every window of `tail`; empty if it is shorter than a window.
pub fn window_hashes(tail: &str) -> Vec<String> {
    tail.as_bytes()
        .windows(WINDOW)
        .map(|w| key(w).iter().map(|b| format!("{b:02x}")).collect())
        .collect()
}

fn parse_hex(hex: &str) -> Option<Key> {
    let bytes = hex.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Maps window hashes back to token ids.
#[derive(Debug, Clone, Default)]
pub struct TailIndex {
    map: HashMap<Key, String>,
}

impl TailIndex {
    /// `hashes` pairs each token id with its hex window hashes.
    pub fn new<'a>(hashes: impl Iterator<Item = (&'a str, &'a [String])>) -> TailIndex {
        let mut map = HashMap::new();
        for (id, list) in hashes {
            for hex in list {
                if let Some(k) = parse_hex(hex) {
                    map.insert(k, id.to_string());
                }
            }
        }
        TailIndex { map }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// (start, end, id) of each maximal span of `text` covered by windows of
    /// one token's tail.
    pub fn find(&self, text: &str) -> Vec<(usize, usize, String)> {
        let mut out: Vec<(usize, usize, String)> = Vec::new();
        if self.map.is_empty() {
            return out;
        }
        let bytes = text.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            if !is_tail_char(bytes[start]) {
                start += 1;
                continue;
            }
            let end = bytes[start..]
                .iter()
                .position(|&b| !is_tail_char(b))
                .map_or(bytes.len(), |n| start + n);
            if end - start >= WINDOW {
                for pos in start..=end - WINDOW {
                    let Some(id) = self.map.get(&key(&bytes[pos..pos + WINDOW])) else {
                        continue;
                    };
                    match out.last_mut() {
                        Some(last) if last.2 == *id && pos <= last.1 => last.1 = pos + WINDOW,
                        _ => out.push((pos, pos + WINDOW, id.clone())),
                    }
                }
            }
            start = end;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{BASE62, BASE64, random_string};

    #[test]
    fn hashes_every_window() {
        let tail = random_string(BASE62, 24);
        let hashes = window_hashes(&tail);
        assert_eq!(hashes.len(), 24 - WINDOW + 1);
        assert!(
            hashes
                .iter()
                .all(|h| h.len() == 32 && !tail.contains(h.as_str()))
        );
        assert!(window_hashes(&tail[..WINDOW - 1]).is_empty());
    }

    #[test]
    fn finds_a_whole_tail_or_any_long_enough_piece_of_it() {
        let tail = random_string(BASE64, 40);
        let hashes = window_hashes(&tail);
        let index = TailIndex::new([("ABCDEFGH", hashes.as_slice())].into_iter());

        let text = format!("curl -d k={tail}&x=1");
        let start = text.find(&tail).unwrap();
        assert_eq!(
            index.find(&text),
            vec![(start, start + 40, "ABCDEFGH".to_string())]
        );

        let piece = &tail[10..10 + WINDOW + 2];
        let text = format!("echo {piece}");
        assert_eq!(
            index.find(&text),
            vec![(5, 5 + piece.len(), "ABCDEFGH".to_string())]
        );
    }

    #[test]
    fn short_pieces_and_unrelated_text_do_not_match() {
        let tail = random_string(BASE62, 32);
        let hashes = window_hashes(&tail);
        let index = TailIndex::new([("ABCDEFGH", hashes.as_slice())].into_iter());
        assert!(index.find(&tail[..WINDOW - 1]).is_empty());
        assert!(index.find(&random_string(BASE62, 200)).is_empty());
    }
}
