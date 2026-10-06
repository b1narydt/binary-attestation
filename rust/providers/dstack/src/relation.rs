//! The `dstack-subject-key-brc100-v1` binding relation (spec §6.2).

use binary_attestation_core::{
    BindingRelationVerifier, Denial, EvidenceBindingEdge, VerifiedComponent, constant_time_eq,
};

use crate::{
    DSTACK_ATTEST_V0_PROVIDER, DSTACK_SUBJECT_KEY_V0_PROVIDER, KmsPins, SUBJECT_KEY_PURPOSE, chain,
    hex,
};

pub const DSTACK_SUBJECT_KEY_BRC100_RELATION: &str = "dstack-subject-key-brc100-v1";
const KMS_ISSUED_PREFIX: &[u8] = b"dstack-kms-issued:";

/// Chains the child's app root to the pinned KMS secp256k1 root through link
/// 1 over `keccak256("dstack-kms-issued:" || app_id || app_root)`, with
/// `app_id` and `key-provider` taken only from the verified parent.
pub struct DstackSubjectKeyBrc100Relation {
    kms: KmsPins,
    ca_spki_hex: String,
}

impl DstackSubjectKeyBrc100Relation {
    pub fn new(kms: KmsPins) -> Result<Self, Denial> {
        kms.validate()?;
        let ca_spki_hex = hex::encode(&kms.ca_spki_der);
        Ok(Self { kms, ca_spki_hex })
    }
}

fn measurement<'a>(component: &'a VerifiedComponent, key: &str) -> Result<&'a str, Denial> {
    component
        .measurements
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(Denial::Malformed)
}

impl BindingRelationVerifier for DstackSubjectKeyBrc100Relation {
    fn relation(&self) -> &'static str {
        DSTACK_SUBJECT_KEY_BRC100_RELATION
    }

    fn verify(
        &self,
        parent: &VerifiedComponent,
        child: &VerifiedComponent,
        edge: &EvidenceBindingEdge,
        expected_binding: [u8; 64],
        _now_ms: u64,
    ) -> Result<(), Denial> {
        if edge.relation != DSTACK_SUBJECT_KEY_BRC100_RELATION
            || edge.evidence.is_some()
            || edge.parent_component_id != parent.component_id
            || edge.child_component_id != child.component_id
        {
            return Err(Denial::Malformed);
        }
        if parent.provider != DSTACK_ATTEST_V0_PROVIDER
            || parent
                .platform
                .get("profile")
                .and_then(serde_json::Value::as_str)
                != Some(DSTACK_ATTEST_V0_PROVIDER)
            || child.provider != DSTACK_SUBJECT_KEY_V0_PROVIDER
            || child
                .platform
                .get("profile")
                .and_then(serde_json::Value::as_str)
                != Some(DSTACK_SUBJECT_KEY_V0_PROVIDER)
        {
            return Err(Denial::UnsupportedProvider);
        }
        // The parent must itself be the directly bound component.
        if !constant_time_eq(&parent.binding_digest.bytes::<64>()?, &expected_binding) {
            return Err(Denial::BindingMismatch);
        }
        let key_provider_id = measurement(parent, "key_provider_id")?;
        if !constant_time_eq(key_provider_id.as_bytes(), self.ca_spki_hex.as_bytes()) {
            return Err(Denial::RootUntrusted);
        }
        let app_id = hex::decode_lower_array::<20>(measurement(parent, "app_id")?)
            .ok_or(Denial::Malformed)?;
        if measurement(child, "purpose")? != SUBJECT_KEY_PURPOSE {
            return Err(Denial::Malformed);
        }
        let app_root = hex::decode_lower_array::<33>(measurement(child, "app_root")?)
            .ok_or(Denial::Malformed)?;
        let link1 = hex::decode_lower(measurement(child, "kms_link1")?).ok_or(Denial::Malformed)?;
        let mut preimage = Vec::with_capacity(KMS_ISSUED_PREFIX.len() + 20 + 33);
        preimage.extend_from_slice(KMS_ISSUED_PREFIX);
        preimage.extend_from_slice(&app_id);
        preimage.extend_from_slice(&app_root);
        let recovered = chain::recover_link(&link1, &chain::keccak256(&preimage))?;
        if !constant_time_eq(&recovered, &self.kms.k256_root) {
            return Err(Denial::RootUntrusted);
        }
        Ok(())
    }
}
