//! Minimal hex helpers (lowercase canonical form).

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(nibble(byte >> 4)));
        out.push(char::from(nibble(byte & 0x0f)));
    }
    out
}

fn nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

/// Decodes lowercase hex only (the canonical spelling BCAP1 uses on the wire).
pub(crate) fn decode_lower(value: &str) -> Option<Vec<u8>> {
    if value
        .bytes()
        .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    decode_any(value)
}

/// Decodes hex of either case (operator-pinned configuration input).
pub(crate) fn decode_any(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

pub(crate) fn decode_lower_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    decode_lower(value)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_uppercase_on_the_wire() {
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(decode_lower("00abff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode_lower("00ABFF"), None);
        assert_eq!(decode_any("00ABFF"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode_lower("abc"), None);
        assert_eq!(decode_lower_array::<2>("abcd"), Some([0xab, 0xcd]));
        assert_eq!(decode_lower_array::<3>("abcd"), None);
    }
}
