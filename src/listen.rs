//! Local HTTP listener that detects planted credentials being *used*.
//!
//! `plant --listen PORT` points configs (AWS `endpoint_url`, npm `registry`,
//! `API_BASE_URL`) at `127.0.0.1:PORT`, so a tool that picks up the fake
//! credentials sends them here instead of to a real provider.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use anyhow::Result;

use crate::matcher;
use crate::state::{Alert, AlertKind, Registry, State};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Reads one HTTP request, answers 403, and returns `use` alerts for every
/// token in the request line, headers or body.
pub fn handle(stream: &mut (impl Read + Write), registry: &Registry, peer: &str) -> Vec<Alert> {
    let (head, body) = read_request(stream);
    let body_message = b"{\"message\":\"Forbidden\"}";
    let mut response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body_message.len()
    )
    .into_bytes();
    response.extend_from_slice(body_message);
    let _ = stream.write_all(&response);
    let _ = stream.flush();

    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = vec![("request line".to_string(), request_line.clone())];
    for line in lines {
        let name = line
            .split(':')
            .next()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        parts.push((format!("{name} header"), line.to_string()));
    }
    parts.push((
        "body".to_string(),
        String::from_utf8_lossy(&body).into_owned(),
    ));

    // (id, encoding) -> where it was seen
    let mut seen: Vec<(matcher::Hit, Vec<String>)> = Vec::new();
    for (label, text) in &parts {
        for hit in matcher::find(text) {
            match seen.iter_mut().find(|(h, _)| *h == hit) {
                Some((_, labels)) => labels.push(label.clone()),
                None => seen.push((hit, vec![label.clone()])),
            }
        }
    }
    seen.into_iter()
        .map(|(hit, labels)| {
            let mut alert =
                Alert::new(AlertKind::Use, "listen").with_token(registry, &hit.id, hit.encoding);
            alert.detail = Some(format!(
                "{} from {peer}; token in {}",
                matcher::redact(&request_line),
                labels.join(", ")
            ));
            alert
        })
        .collect()
}

/// The header block (without the blank line) and up to `Content-Length`
/// bytes of body, both size-limited.
fn read_request(stream: &mut impl Read) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break Some(i);
        }
        if buf.len() > MAX_HEADER_BYTES {
            break None;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let Some(end) = header_end else {
        return (String::from_utf8_lossy(&buf).into_owned(), Vec::new());
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut body = buf[end + 4..].to_vec();
    let length = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY_BYTES);
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length.max(body.len().min(MAX_BODY_BYTES)));
    (head, body)
}

/// Accepts connections forever, calling `on_alert` for each alert.
pub fn serve(listener: TcpListener, state: &State, mut on_alert: impl FnMut(&Alert)) -> Result<()> {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let registry = state.load_registry().unwrap_or_default();
        for alert in handle(&mut stream, &registry, &peer) {
            on_alert(&alert);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Kind, Plant, PlantedFile, TokenField};
    use crate::token::{MARKER, new_id};
    use std::net::TcpStream;

    fn registry() -> (Registry, String) {
        let id = new_id(|_| false);
        let reg = Registry {
            plants: vec![Plant {
                id: "p-test".into(),
                created: String::new(),
                root: "/sb".into(),
                files: vec![PlantedFile {
                    path: "/sb/.aws/credentials".into(),
                    kind: Kind::Aws,
                    sha256: String::new(),
                    tokens: vec![TokenField {
                        id: id.clone(),
                        field: "aws_access_key_id".into(),
                    }],
                }],
                created_dirs: vec![],
                listen: Some(1),
            }],
        };
        (reg, id)
    }

    /// Sends `request` over a real loopback connection and returns the
    /// alerts and the raw response.
    fn exchange(request: &[u8], reg: &Registry) -> (Vec<Alert>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let request = request.to_vec();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&request).unwrap();
            let mut response = String::new();
            s.read_to_string(&mut response).unwrap();
            response
        });
        let (mut server, peer) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let alerts = handle(&mut server, reg, &peer.to_string());
        drop(server);
        (alerts, client.join().unwrap())
    }

    #[test]
    fn token_in_authorization_header_is_use() {
        let (reg, id) = registry();
        let request = format!(
            "GET /?list-type=2 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: AWS4-HMAC-SHA256 \
             Credential=AKIA{MARKER}{id}/20261112/us-east-1/s3/aws4_request\r\n\r\n"
        );
        let (alerts, response) = exchange(request.as_bytes(), &reg);
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.kind, Some(AlertKind::Use));
        assert_eq!(alert.source, "listen");
        assert_eq!(alert.field.as_deref(), Some("aws_access_key_id"));
        let detail = alert.detail.as_deref().unwrap();
        assert!(
            detail.contains("GET /?list-type=2") && detail.contains("authorization"),
            "{detail}"
        );
        assert!(matcher::find(detail).is_empty(), "{detail}");
    }

    #[test]
    fn token_in_body_is_use() {
        let (reg, id) = registry();
        let body = format!("{{\"token\":\"{MARKER}{id}\"}}");
        let request = format!(
            "POST /-/v1/login HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (alerts, _) = exchange(request.as_bytes(), &reg);
        assert_eq!(
            alerts.iter().filter_map(|a| a.kind).collect::<Vec<_>>(),
            vec![AlertKind::Use]
        );
        assert!(alerts[0].detail.as_deref().unwrap().contains("body"));
    }

    #[test]
    fn requests_without_tokens_are_quiet_but_refused() {
        let (reg, _) = registry();
        let (alerts, response) = exchange(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", &reg);
        assert!(alerts.is_empty());
        assert!(response.starts_with("HTTP/1.1 403"));
    }
}
