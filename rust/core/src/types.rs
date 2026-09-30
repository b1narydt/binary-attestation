use std::collections::{BTreeMap, HashSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{Denial, binding_digest, jcs_bytes};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_CHALLENGE_TTL_MS: u64 = 300_000;
pub const MAX_STRING_BYTES: usize = 1_024;
pub const MAX_COMPONENTS: usize = 32;
pub const MAX_COMPONENT_EVIDENCE: usize = 2 * 1024 * 1024;
pub const MAX_COMPONENT_ENDORSEMENTS: usize = 4 * 1024 * 1024;
pub const MAX_BINDING_EDGE_EVIDENCE: usize = 2 * 1024 * 1024;
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BINDING_EDGES: usize = 64;
pub const MAX_CLAIM_KEYS: usize = 256;

/// Strict unpadded base64url text.  The original canonical text is retained
/// so it can safely be serialized without alternate encodings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct B64Url(String);

impl B64Url {
    pub fn new(value: impl Into<String>) -> Result<Self, Denial> {
        let value = value.into();
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err(Denial::Malformed);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&value)
            .map_err(|_| Denial::Malformed)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(Denial::Malformed);
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        // Encoding arbitrary bytes with URL_SAFE_NO_PAD is canonical by construction.
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(&self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&self.0)
            .expect("B64Url is validated at construction")
    }

    pub fn bytes<const N: usize>(&self) -> Result<[u8; N], Denial> {
        let decoded = self.decode();
        decoded.try_into().map_err(|_| Denial::Malformed)
    }

    pub fn decoded_len(&self) -> usize {
        // Validated base64url: this cannot fail.
        self.decode().len()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for B64Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Canonical unsigned 64-bit decimal, represented as a u64 after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U64Decimal(u64);

impl U64Decimal {
    pub fn new(value: &str) -> Result<Self, Denial> {
        if value.is_empty()
            || value.len() > 20
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Denial::Malformed);
        }
        value.parse().map(Self).map_err(|_| Denial::Malformed)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Serialize for U64Decimal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for U64Decimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(de::Error::custom)
    }
}

pub fn validate_text(value: &str) -> Result<(), Denial> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value.contains('\0')
        || value.nfc().collect::<String>() != value
    {
        return Err(Denial::Malformed);
    }
    Ok(())
}

pub fn validate_brc100_key(value: &str) -> Result<(), Denial> {
    if value.len() != 66
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || value.as_bytes().first() != Some(&b'0')
        || !matches!(value.as_bytes().get(1), Some(b'2' | b'3'))
    {
        return Err(Denial::Malformed);
    }
    let bytes = hex_decode(value)?;
    if bytes
        .first()
        .copied()
        .filter(|byte| *byte == 2 || *byte == 3)
        .is_none()
    {
        return Err(Denial::Malformed);
    }
    PublicKey::from_sec1_bytes(&bytes).map_err(|_| Denial::Malformed)?;
    Ok(())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, Denial> {
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16).ok_or(Denial::Malformed)?;
        let low = (pair[1] as char).to_digit(16).ok_or(Denial::Malformed)?;
        output.push(((high << 4) | low) as u8);
    }
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationSubject {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

impl AttestationSubject {
    pub fn validate(&self) -> Result<(), Denial> {
        validate_text(&self.kind)?;
        validate_text(&self.value)?;
        if self.kind == "brc100-public-key" {
            validate_brc100_key(&self.value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderPolicyArtifact {
    pub artifact_id: String,
    pub provider: String,
    pub media_type: String,
    pub canonicalization: String,
    pub content: B64Url,
    pub digest: B64Url,
}

impl ProviderPolicyArtifact {
    pub fn validate(&self) -> Result<(), Denial> {
        for value in [
            &self.artifact_id,
            &self.provider,
            &self.media_type,
            &self.canonicalization,
        ] {
            validate_text(value)?;
        }
        if self.digest.decoded_len() != 32
            || !constant_time_eq(
                &Sha256::digest(self.content.decode()),
                &self.digest.decode(),
            )
        {
            return Err(Denial::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecuritySnapshotBody {
    pub security_epoch: U64Decimal,
    pub policy_id: String,
    pub policy_digest: B64Url,
    pub provider_artifacts: Vec<ProviderPolicyArtifact>,
    pub trust_material: serde_json::Map<String, serde_json::Value>,
    pub valid_from_ms: U64Decimal,
    pub valid_until_ms: U64Decimal,
    pub signer_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedSecuritySnapshot {
    pub body: SecuritySnapshotBody,
    pub trust_digest: B64Url,
    pub algorithm: String,
    pub signature: B64Url,
}

impl SignedSecuritySnapshot {
    pub fn validate(&self) -> Result<(), Denial> {
        let body = &self.body;
        for value in [&body.policy_id, &body.signer_key_id, &self.algorithm] {
            validate_text(value)?;
        }
        if body.policy_digest.decoded_len() != 32 || self.trust_digest.decoded_len() != 32 {
            return Err(Denial::Malformed);
        }
        if body.valid_from_ms >= body.valid_until_ms {
            return Err(Denial::TrustSnapshotInvalid);
        }
        if body.provider_artifacts.len() > MAX_COMPONENTS {
            return Err(Denial::ResourceLimit);
        }
        for artifact in &body.provider_artifacts {
            artifact.validate()?;
        }
        let bytes = jcs_bytes(&serde_json::to_value(body).map_err(|_| Denial::Malformed)?)?;
        if !constant_time_eq(&Sha256::digest(bytes), &self.trust_digest.decode()) {
            return Err(Denial::TrustSnapshotInvalid);
        }
        Ok(())
    }

    pub fn is_valid_at(&self, now_ms: u64) -> bool {
        self.body.valid_from_ms.get() <= now_ms && now_ms < self.body.valid_until_ms.get()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub protocol_version: u8,
    pub challenge_id: B64Url,
    pub nonce: B64Url,
    pub subject: AttestationSubject,
    pub audience: String,
    pub context: String,
    pub context_digest: B64Url,
    pub policy_id: String,
    pub policy_digest: B64Url,
    pub security_epoch: U64Decimal,
    pub trust_digest: B64Url,
    pub issued_at_ms: U64Decimal,
    pub expires_at_ms: U64Decimal,
}

impl Challenge {
    pub fn validate(&self) -> Result<(), Denial> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(Denial::UnsupportedVersion);
        }
        self.subject.validate()?;
        for value in [&self.audience, &self.context, &self.policy_id] {
            validate_text(value)?;
        }
        if self.challenge_id.decoded_len() != 16
            || self.nonce.decoded_len() != 32
            || self.context_digest.decoded_len() != 32
            || self.policy_digest.decoded_len() != 32
            || self.trust_digest.decoded_len() != 32
            || self.issued_at_ms >= self.expires_at_ms
            || self.expires_at_ms.get() - self.issued_at_ms.get() > MAX_CHALLENGE_TTL_MS
        {
            return Err(Denial::Malformed);
        }
        Ok(())
    }

    pub fn binding_digest(&self) -> Result<[u8; 64], Denial> {
        binding_digest(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceComponent {
    pub component_id: String,
    pub provider: String,
    pub media_type: String,
    pub evidence: B64Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endorsements: Option<B64Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untrusted_metadata: Option<BTreeMap<String, String>>,
}

impl EvidenceComponent {
    pub fn validate(&self) -> Result<(), Denial> {
        for value in [&self.component_id, &self.provider, &self.media_type] {
            validate_text(value)?;
        }
        if self.evidence.decoded_len() > MAX_COMPONENT_EVIDENCE
            || self
                .endorsements
                .as_ref()
                .is_some_and(|value| value.decoded_len() > MAX_COMPONENT_ENDORSEMENTS)
        {
            return Err(Denial::ResourceLimit);
        }
        if let Some(metadata) = &self.untrusted_metadata {
            for (key, value) in metadata {
                validate_text(key)?;
                validate_text(value)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceBindingEdge {
    pub parent_component_id: String,
    pub child_component_id: String,
    pub relation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<B64Url>,
}

impl EvidenceBindingEdge {
    pub fn validate(&self) -> Result<(), Denial> {
        for value in [
            &self.parent_component_id,
            &self.child_component_id,
            &self.relation,
        ] {
            validate_text(value)?;
        }
        if self
            .evidence
            .as_ref()
            .is_some_and(|value| value.decoded_len() > MAX_BINDING_EDGE_EVIDENCE)
        {
            return Err(Denial::ResourceLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceBundle {
    pub protocol_version: u8,
    pub challenge_id: B64Url,
    pub subject: AttestationSubject,
    pub components: Vec<EvidenceComponent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_edges: Option<Vec<EvidenceBindingEdge>>,
}

impl EvidenceBundle {
    pub fn validate(&self) -> Result<(), Denial> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(Denial::UnsupportedVersion);
        }
        self.subject.validate()?;
        if self.challenge_id.decoded_len() != 16 {
            return Err(Denial::Malformed);
        }
        if self.components.len() > MAX_COMPONENTS || self.components.is_empty() {
            return Err(Denial::ResourceLimit);
        }
        let mut ids = HashSet::new();
        let mut decoded_total = 0usize;
        for component in &self.components {
            component.validate()?;
            if !ids.insert(&component.component_id) {
                return Err(Denial::Malformed);
            }
            decoded_total = decoded_total
                .checked_add(component.evidence.decoded_len())
                .and_then(|total| {
                    total.checked_add(
                        component
                            .endorsements
                            .as_ref()
                            .map_or(0, B64Url::decoded_len),
                    )
                })
                .ok_or(Denial::ResourceLimit)?;
        }
        if decoded_total > MAX_BUNDLE_BYTES {
            return Err(Denial::ResourceLimit);
        }
        let edges = self.binding_edges.as_deref().unwrap_or_default();
        if edges.len() > MAX_BINDING_EDGES {
            return Err(Denial::ResourceLimit);
        }
        for edge in edges {
            edge.validate()?;
            if !ids.contains(&edge.parent_component_id) || !ids.contains(&edge.child_component_id) {
                return Err(Denial::Malformed);
            }
            decoded_total = decoded_total
                .checked_add(edge.evidence.as_ref().map_or(0, B64Url::decoded_len))
                .ok_or(Denial::ResourceLimit)?;
        }
        if decoded_total > MAX_BUNDLE_BYTES {
            return Err(Denial::ResourceLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedComponent {
    pub component_id: String,
    pub provider: String,
    pub evidence_digest: B64Url,
    pub binding_digest: B64Url,
    pub platform: BTreeMap<String, serde_json::Value>,
    pub measurements: BTreeMap<String, serde_json::Value>,
    pub tcb: BTreeMap<String, serde_json::Value>,
    pub advisories: Vec<String>,
    pub valid_until_ms: U64Decimal,
}

impl VerifiedComponent {
    pub fn validate(&self) -> Result<(), Denial> {
        for value in [&self.component_id, &self.provider] {
            validate_text(value)?;
        }
        if self.evidence_digest.decoded_len() != 32 || self.binding_digest.decoded_len() != 64 {
            return Err(Denial::Malformed);
        }
        if self.platform.len() > MAX_CLAIM_KEYS
            || self.measurements.len() > MAX_CLAIM_KEYS
            || self.tcb.len() > MAX_CLAIM_KEYS
        {
            return Err(Denial::ResourceLimit);
        }
        for value in self
            .advisories
            .iter()
            .chain(self.platform.keys())
            .chain(self.measurements.keys())
            .chain(self.tcb.keys())
        {
            validate_text(value)?;
        }
        for value in self
            .platform
            .values()
            .chain(self.measurements.values())
            .chain(self.tcb.values())
        {
            validate_claim_value(value)?;
        }
        Ok(())
    }
}

fn validate_claim_value(value: &serde_json::Value) -> Result<(), Denial> {
    match value {
        serde_json::Value::String(value) => validate_text(value),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Ok(()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Err(Denial::Malformed)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedClaims {
    pub protocol_version: u8,
    pub subject: AttestationSubject,
    pub audience: String,
    pub context: String,
    pub context_digest: B64Url,
    pub policy_id: String,
    pub policy_digest: B64Url,
    pub security_epoch: U64Decimal,
    pub trust_digest: B64Url,
    pub binding_digest: B64Url,
    pub subject_binding: String,
    pub components: Vec<VerifiedComponent>,
    pub verified_at_ms: U64Decimal,
    pub valid_until_ms: U64Decimal,
}

impl VerifiedClaims {
    pub fn from_challenge(
        challenge: &Challenge,
        components: Vec<VerifiedComponent>,
        subject_binding: String,
        verified_at_ms: u64,
        valid_until_ms: u64,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            subject: challenge.subject.clone(),
            audience: challenge.audience.clone(),
            context: challenge.context.clone(),
            context_digest: challenge.context_digest.clone(),
            policy_id: challenge.policy_id.clone(),
            policy_digest: challenge.policy_digest.clone(),
            security_epoch: challenge.security_epoch,
            trust_digest: challenge.trust_digest.clone(),
            binding_digest: B64Url::from_bytes(
                &challenge.binding_digest().expect("validated challenge"),
            ),
            subject_binding,
            components,
            verified_at_ms: U64Decimal(verified_at_ms),
            valid_until_ms: U64Decimal(valid_until_ms),
        }
    }
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |different, (left, right)| different | (left ^ right))
        == 0
}
