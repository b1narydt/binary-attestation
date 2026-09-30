use serde::Serialize;

use crate::Denial;

/// RFC 8785 JCS bytes, including its ECMAScript-number and UTF-16 property
/// ordering rules. `serde_jcs` is used rather than approximating those rules.
pub fn jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Denial> {
    serde_jcs::to_vec(value).map_err(|_| Denial::Malformed)
}
