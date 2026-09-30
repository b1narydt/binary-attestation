use sha2::{Digest, Sha256, Sha512};

use crate::{Challenge, Denial};

const CHALLENGE_DOMAIN: &[u8] = b"BINARY-BCAP1-CHALLENGE\0";
const PROVIDER_BINDING_DOMAIN: &[u8] = b"BINARY-BCAP1-PROVIDER-BINDING\0";

/// Exact, length-delimited BCAP1 transcript preimage (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptPreimage(Vec<u8>);

impl TranscriptPreimage {
    pub fn for_challenge(challenge: &Challenge) -> Result<Self, Denial> {
        challenge.validate()?;
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(CHALLENGE_DOMAIN);
        field(&mut output, &challenge.challenge_id.decode())?;
        field(&mut output, &challenge.nonce.decode())?;
        field(&mut output, challenge.subject.kind.as_bytes())?;
        field(&mut output, challenge.subject.value.as_bytes())?;
        field(&mut output, challenge.audience.as_bytes())?;
        field(&mut output, challenge.context.as_bytes())?;
        field(&mut output, &challenge.context_digest.decode())?;
        field(&mut output, challenge.policy_id.as_bytes())?;
        field(&mut output, &challenge.policy_digest.decode())?;
        output.extend_from_slice(&challenge.security_epoch.get().to_be_bytes());
        field(&mut output, &challenge.trust_digest.decode())?;
        output.extend_from_slice(&challenge.issued_at_ms.get().to_be_bytes());
        output.extend_from_slice(&challenge.expires_at_ms.get().to_be_bytes());
        Ok(Self(output))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub fn binding_digest(challenge: &Challenge) -> Result<[u8; 64], Denial> {
    let digest = Sha512::digest(TranscriptPreimage::for_challenge(challenge)?.as_bytes());
    Ok(digest.into())
}

/// Registered derivation for a provider binding field shorter than 64 bytes.
pub fn provider_binding_digest(
    provider: &str,
    binding_digest: &[u8; 64],
) -> Result<[u8; 32], Denial> {
    crate::validate_text(provider)?;
    let mut preimage = Vec::with_capacity(PROVIDER_BINDING_DOMAIN.len() + provider.len() + 68);
    preimage.extend_from_slice(PROVIDER_BINDING_DOMAIN);
    field(&mut preimage, provider.as_bytes())?;
    preimage.extend_from_slice(binding_digest);
    Ok(Sha256::digest(preimage).into())
}

fn field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Denial> {
    let length = u32::try_from(value.len()).map_err(|_| Denial::ResourceLimit)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
