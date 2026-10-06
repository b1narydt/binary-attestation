//! The `dstack-subject-key-v0` child component (spec §6.2, frozen v0).

use std::collections::BTreeMap;

use binary_attestation_core::{
    B64Url, Denial, EvidenceComponent, EvidenceVerifier, U64Decimal, VerifiedComponent, jcs_bytes,
    validate_brc100_key,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{chain, hex};

pub const DSTACK_SUBJECT_KEY_V0_PROVIDER: &str = "dstack-subject-key-v0";
pub const DSTACK_SUBJECT_KEY_MEDIA_TYPE: &str =
    "application/vnd.atlas.dstack-subject-key+json;version=1";
/// The only purpose frozen v0 evidence may claim.
pub const SUBJECT_KEY_PURPOSE: &str = "identity";
/// Bound on the JCS document (two 65-byte links, a DER signature, a key).
pub const MAX_SUBJECT_KEY_EVIDENCE: usize = 4 * 1024;

const SUBJECT_PROOF_DOMAIN: &[u8] = b"BINARY-BCAP1-SUBJECT-PROOF\0";

/// `SHA-256("BINARY-BCAP1-SUBJECT-PROOF\0" || binding_digest)`.
pub fn subject_proof_digest(binding_digest: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SUBJECT_PROOF_DOMAIN);
    hasher.update(binding_digest);
    hasher.finalize().into()
}

/// The §6.2 evidence object (deny-unknown-fields; JCS on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectKeyEvidence {
    pub public_key: String,
    pub signature: B64Url,
    pub key_claim: B64Url,
    pub signature_chain: Vec<B64Url>,
}

impl SubjectKeyEvidence {
    /// The frozen-v0 claim bytes for a public key: `identity:<hex>`.
    pub fn key_claim_for(public_key: &str) -> Vec<u8> {
        format!("{SUBJECT_KEY_PURPOSE}:{public_key}").into_bytes()
    }

    /// Canonical (JCS) wire bytes.
    pub fn to_jcs(&self) -> Result<Vec<u8>, Denial> {
        jcs_bytes(self)
    }
}

/// Verifies the child's shape, public key, subject proof and link-0 recovery.
/// Its output never binds the BCAP1 digest directly.
#[derive(Debug, Default, Clone, Copy)]
pub struct DstackSubjectKeyV0Verifier;

impl DstackSubjectKeyV0Verifier {
    pub fn new() -> Self {
        Self
    }
}

impl EvidenceVerifier for DstackSubjectKeyV0Verifier {
    fn provider(&self) -> &'static str {
        DSTACK_SUBJECT_KEY_V0_PROVIDER
    }

    fn verify(
        &self,
        component: &EvidenceComponent,
        expected_binding: [u8; 64],
        _now_ms: u64,
    ) -> Result<VerifiedComponent, Denial> {
        if component.provider != DSTACK_SUBJECT_KEY_V0_PROVIDER
            || component.media_type != DSTACK_SUBJECT_KEY_MEDIA_TYPE
            || component.endorsements.is_some()
        {
            return Err(Denial::Malformed);
        }
        let evidence = component
            .evidence
            .decode_with_limit(MAX_SUBJECT_KEY_EVIDENCE)?;
        let evidence_digest: [u8; 32] = Sha256::digest(&evidence).into();
        let parsed: SubjectKeyEvidence =
            serde_json::from_slice(&evidence).map_err(|_| Denial::Malformed)?;
        if parsed.to_jcs()? != evidence {
            return Err(Denial::Malformed);
        }
        validate_brc100_key(&parsed.public_key)?;
        let public_key = hex::decode_lower(&parsed.public_key).ok_or(Denial::Malformed)?;
        let claim = parsed.key_claim.decode_with_limit(256)?;
        if claim != SubjectKeyEvidence::key_claim_for(&parsed.public_key) {
            return Err(Denial::Malformed);
        }
        if parsed.signature_chain.len() != 2 {
            return Err(Denial::Malformed);
        }
        let link0 = parsed.signature_chain[0].decode_with_limit(65)?;
        let link1 = parsed.signature_chain[1].decode_with_limit(65)?;
        if link0.len() != 65 || link1.len() != 65 {
            return Err(Denial::Malformed);
        }
        // Link 1 is recovered by the relation (it needs the parent's app_id);
        // here it must at least be a well-formed low-S link in dstack's range.
        chain::recover_link(&link1, &[0; 32])?;
        let signature = parsed.signature.decode_with_limit(80)?;
        chain::verify_der_low_s(
            &public_key,
            &signature,
            &subject_proof_digest(&expected_binding),
        )?;
        let app_root = chain::recover_link(&link0, &chain::keccak256(&claim))?;
        Ok(VerifiedComponent {
            component_id: component.component_id.clone(),
            provider: DSTACK_SUBJECT_KEY_V0_PROVIDER.to_owned(),
            evidence_digest: B64Url::from_bytes(&evidence_digest),
            binding_digest: B64Url::from_bytes(&[0; 64]),
            platform: BTreeMap::from([
                ("profile".to_owned(), DSTACK_SUBJECT_KEY_V0_PROVIDER.into()),
                ("key_claim_profile".to_owned(), "dstack-getkey-v0".into()),
            ]),
            measurements: BTreeMap::from([
                ("public_key".to_owned(), parsed.public_key.clone().into()),
                ("app_root".to_owned(), hex::encode(&app_root).into()),
                ("purpose".to_owned(), SUBJECT_KEY_PURPOSE.into()),
                ("kms_link1".to_owned(), hex::encode(&link1).into()),
            ]),
            tcb: BTreeMap::new(),
            advisories: Vec::new(),
            // No time-bound endorsement of its own: validity comes from the
            // parent through composition and from the challenge.
            valid_until_ms: U64Decimal::new(&u64::MAX.to_string())?,
        })
    }
}
