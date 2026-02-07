//! Input parsing utilities for Lattice clients.

/// Extract a raw 16-byte NTLM hash from a line.
///
/// Accepts either a bare 32-hex string or a colon-delimited record
/// where the NTLM hash appears in one of the fields.
pub fn extract_ntlm_hash(line: &str) -> Option<[u8; 16]> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut candidate: Option<&str> = None;
    if trimmed.contains(':') {
        for part in trimmed.split(':') {
            if is_hex32(part) {
                candidate = Some(part);
            }
        }
    } else if is_hex32(trimmed) {
        candidate = Some(trimmed);
    }

    let candidate = candidate?;
    let mut out = [0u8; 16];
    if hex::decode_to_slice(candidate.as_bytes(), &mut out).is_ok() {
        Some(out)
    } else {
        None
    }
}

fn is_hex32(s: &str) -> bool {
    if s.len() != 32 {
        return false;
    }
    s.as_bytes().iter().all(|b| match b {
        b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::extract_ntlm_hash;

    #[test]
    fn parses_plain_hash() {
        let line = "8846f7eaee8fb117ad06bdd830b7586c";
        let hash = extract_ntlm_hash(line).expect("hash");
        assert_eq!(hex::encode(hash), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn parses_colon_record() {
        let line = "user:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::";
        let hash = extract_ntlm_hash(line).expect("hash");
        assert_eq!(hex::encode(hash), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn ignores_invalid() {
        assert!(extract_ntlm_hash("not-a-hash").is_none());
    }
}
