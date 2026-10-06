//! secp256k1 helpers for the frozen-v0 `GetKey` chain and the subject proof.

use binary_attestation_core::Denial;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha3::{Digest, Keccak256};

pub(crate) fn keccak256(message: &[u8]) -> [u8; 32] {
    Keccak256::digest(message).into()
}

/// Parses a raw 64-byte `r || s` signature, refusing high-S (malleable) forms.
fn low_s_signature(raw: &[u8]) -> Result<Signature, Denial> {
    let signature = Signature::from_slice(raw).map_err(|_| Denial::SignatureInvalid)?;
    if signature.normalize_s().is_some() {
        return Err(Denial::SignatureInvalid);
    }
    Ok(signature)
}

/// Recovers the compressed public key from a dstack 65-byte `r || s || v`
/// link over `digest`. Only `v ∈ {0, 1}` (what dstack emits) and low-S
/// signatures are accepted.
pub(crate) fn recover_link(link: &[u8], digest: &[u8; 32]) -> Result<[u8; 33], Denial> {
    if link.len() != 65 {
        return Err(Denial::Malformed);
    }
    let recovery = match link[64] {
        0 => RecoveryId::new(false, false),
        1 => RecoveryId::new(true, false),
        _ => return Err(Denial::SignatureInvalid),
    };
    let signature = low_s_signature(&link[..64])?;
    let key = VerifyingKey::recover_from_prehash(digest, &signature, recovery)
        .map_err(|_| Denial::SignatureInvalid)?;
    key.to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| Denial::SignatureInvalid)
}

/// Verifies a strict-DER, low-S ECDSA signature by `public_key` (compressed
/// SEC1) over the 32-byte `digest`, signed as-is.
pub(crate) fn verify_der_low_s(
    public_key: &[u8],
    der: &[u8],
    digest: &[u8; 32],
) -> Result<(), Denial> {
    let signature = Signature::from_der(der).map_err(|_| Denial::SignatureInvalid)?;
    // Strict DER: the canonical re-encoding must reproduce the input bytes.
    if signature.to_der().as_bytes() != der {
        return Err(Denial::SignatureInvalid);
    }
    if signature.normalize_s().is_some() {
        return Err(Denial::SignatureInvalid);
    }
    let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| Denial::Malformed)?;
    key.verify_prehash(digest, &signature)
        .map_err(|_| Denial::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn recover_and_verify_round_trip() {
        let key = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let digest = keccak256(b"identity:00");
        let (signature, recovery) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut link = signature.to_bytes().to_vec();
        link.push(recovery.to_byte());
        let expected: [u8; 33] = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(recover_link(&link, &digest), Ok(expected));
        link[64] = 27;
        assert_eq!(recover_link(&link, &digest), Err(Denial::SignatureInvalid));
        assert_eq!(recover_link(&link[..64], &digest), Err(Denial::Malformed));

        let proof = key.sign_prehash_recoverable(&digest).unwrap().0;
        let der = proof.to_der();
        verify_der_low_s(&expected, der.as_bytes(), &digest).unwrap();
        assert_eq!(
            verify_der_low_s(&expected, der.as_bytes(), &[1; 32]),
            Err(Denial::SignatureInvalid)
        );
        assert_eq!(
            verify_der_low_s(&[0; 33], der.as_bytes(), &digest),
            Err(Denial::Malformed)
        );
    }
}
