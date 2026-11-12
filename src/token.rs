//! Token ids: the part of every planted value that identifies it.
//!
//! A planted value contains `TRIPWIRE` followed by an 8-character id in
//! base32 (A–Z, 2–7): 6 random characters and 2 check characters.

use sha2::{Digest, Sha256};

pub const MARKER: &str = "TRIPWIRE";
pub const ID_LEN: usize = 8;
const RANDOM_LEN: usize = 6;

pub const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Returns a new id for which `taken` is false.
pub fn new_id(taken: impl Fn(&str) -> bool) -> String {
    loop {
        let mut id = random_string(BASE32, RANDOM_LEN);
        id.push_str(&check_chars(&id));
        if !taken(&id) {
            return id;
        }
    }
}

/// True if `id` is 8 uppercase base32 characters with valid check characters.
pub fn is_valid_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id.bytes().all(|b| BASE32.contains(&b))
        && id[RANDOM_LEN..] == check_chars(&id[..RANDOM_LEN])
}

fn check_chars(random: &str) -> String {
    let digest = Sha256::new()
        .chain_update(b"agent-tripwire:")
        .chain_update(random.as_bytes())
        .finalize();
    let bits = (u16::from(digest[0]) << 2) | u16::from(digest[1] >> 6);
    [bits >> 5, bits & 0x1f]
        .iter()
        .map(|&i| BASE32[usize::from(i)] as char)
        .collect()
}

/// `n` characters drawn uniformly from `alphabet` using the OS random source.
pub fn random_string(alphabet: &[u8], n: usize) -> String {
    assert!(!alphabet.is_empty() && alphabet.len() <= 256);
    // Rejection sampling keeps the distribution uniform for any alphabet size.
    let limit = 256 - 256 % alphabet.len();
    let mut out = String::with_capacity(n);
    let mut buf = [0u8; 64];
    while out.len() < n {
        getrandom::fill(&mut buf).expect("OS random source unavailable");
        for &b in &buf {
            if usize::from(b) < limit && out.len() < n {
                out.push(alphabet[usize::from(b) % alphabet.len()] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn new_id_is_valid_base32() {
        let id = new_id(|_| false);
        assert_eq!(id.len(), ID_LEN);
        assert!(id.bytes().all(|b| BASE32.contains(&b)), "{id}");
        assert!(is_valid_id(&id), "{id}");
    }

    #[test]
    fn corrupted_check_characters_are_rejected() {
        let id = new_id(|_| false);
        let mut bytes = id.into_bytes();
        let last = bytes[ID_LEN - 1];
        bytes[ID_LEN - 1] = if last == b'A' { b'B' } else { b'A' };
        assert!(!is_valid_id(std::str::from_utf8(&bytes).unwrap()));
    }

    #[test]
    fn rejects_wrong_length_case_and_alphabet() {
        let id = new_id(|_| false);
        assert!(!is_valid_id(&id[..ID_LEN - 1]));
        assert!(!is_valid_id(&id.to_lowercase()) || id.to_lowercase() == id);
        assert!(!is_valid_id("AAAAAA01"));
    }

    #[test]
    fn most_random_words_fail_the_check() {
        let valid = (0..4096)
            .map(|_| random_string(BASE32, ID_LEN))
            .filter(|w| is_valid_id(w))
            .count();
        // Expected 4 (1 in 1024); allow generous slack.
        assert!(valid < 40, "{valid} of 4096 random words passed");
    }

    #[test]
    fn new_id_skips_taken_ids() {
        let mut seen = HashSet::new();
        for _ in 0..500 {
            let id = new_id(|c| seen.contains(c));
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn random_string_uses_alphabet() {
        let s = random_string(b"xy", 64);
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|b| b == b'x' || b == b'y'));
        assert!(s.contains('x') && s.contains('y'));
    }
}
