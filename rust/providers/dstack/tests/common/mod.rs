//! Shared fixture harness for the dstack 0.5.9 production captures.
//!
//! Everything here is loaded from `tests/fixtures/dstack-0.5.9-prod/` (see its
//! README for provenance). Nothing is fabricated: tampered variants are derived
//! from the live bytes inside the individual tests.
#![allow(dead_code)]

use std::{fs, path::PathBuf};

use binary_attestation_core::{
    B64Url, Challenge, Clock, Denial, EvidenceBindingEdge, EvidenceComponent,
    SignedSecuritySnapshot, U64Decimal, jcs_bytes,
};
use binary_attestation_dstack::{
    BootMeasurements, DSTACK_ATTEST_V0_MEDIA_TYPE, DSTACK_ATTEST_V0_PROVIDER,
    DSTACK_SUBJECT_KEY_BRC100_RELATION, DSTACK_SUBJECT_KEY_MEDIA_TYPE,
    DSTACK_SUBJECT_KEY_V0_PROVIDER, DcapRootV1, DstackAttestV0Verifier, DstackBrc100IdentityPolicy,
    DstackPolicyArtifactV1, DstackSnapshotPlugins, DstackSubjectKeyBrc100Relation,
    DstackSubjectKeyV0Verifier, DstackTrust, KmsPins, PinnedCollateral,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::der::{DecodePem, Encode};

pub const PARENT_ID: &str = "dstack-cvm";
pub const CHILD_ID: &str = "dstack-subject-key";

/// Production dstack-0.5.9 OS image (`os_image_hash`, from `info.json`).
pub const PROD_OS_IMAGE_HASH: &str =
    "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033";
/// The dstack-0.5.9 *dev* image captured on the same account; never allowed.
pub const DEV_OS_IMAGE_HASH: &str =
    "de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9";
pub const COMPOSE_HASH: &str = "fc19b07126115b47869928e86bfa1170e10e51110eb046be0c0b97abd515b4d4";
pub const APP_ID: &str = "3cfe3bb849a0d4484ac0f579b45383d287f90fce";
pub const INSTANCE_ID: &str = "6fc1d0f4bb81b981886b4250845079b65c874625";
pub const MR_KMS: &str = "de46a8d7a3b3660b01a77c5d2829c31ceedae0419b7bb2716c47c9224e0f4c1e";
pub const APP_ID_20261006: &str = "fb0130ad4d6f15107991a8551b6f7fe2aa78cce0";
pub const COMPOSE_HASH_20261006: &str =
    "a49aa45767fc6c6fc549dbf595dead3a22d882f531a3fc0c524171c5eb2787cf";
pub const VM_CONFIG_SHA256_20261006: &str =
    "848831ae8b31ea11155965aca53602c5254782d83ca5da16bf499207221daa64";
pub const KMS_K256_ROOT: &str =
    "0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1";
pub const FMSPC: &str = "20A06F000000";
/// `tcbInfo.nextUpdate` = 2026-11-05T00:26:11Z, the earliest expiry across the
/// pinned collateral (PCK CRL 00:27:34Z, QE identity 00:44:03Z, root CRL 2027,
/// PCK leaf 2033).
pub const COLLATERAL_EARLIEST_EXPIRY_MS: u64 = 1_793_838_371_000;
/// Oldest freshness-floor time: TCB info's 2026-10-06T00:26:11Z issue date.
/// The QE identity and PCK CRL are newer; the annual root CRL is excluded.
pub const COLLATERAL_ISSUED_MS: u64 = 1_791_246_371_000;

pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dstack-0.5.9-prod")
}

pub fn fixture_bytes(relative: &str) -> Vec<u8> {
    fs::read(fixture_dir().join(relative)).unwrap_or_else(|e| panic!("fixture {relative}: {e}"))
}

pub fn hex_decode(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd hex length");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    request: serde_json::Value,
    #[serde(rename = "agentResponseWithoutKey")]
    agent_response_without_key: AgentResponse,
    #[serde(rename = "keyLength")]
    key_length: usize,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "subjectProofSignatureDer")]
    subject_proof_signature_der: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentResponse {
    signature_chain: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub public_key: String,
    pub subject_proof_der: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub name: &'static str,
    pub challenge: Challenge,
    pub envelope: Vec<u8>,
    pub binding: [u8; 64],
    pub identity: Identity,
}

impl Probe {
    pub fn load(name: &'static str) -> Self {
        let challenge: Challenge =
            serde_json::from_slice(&fixture_bytes(&format!("{name}/challenge.json")))
                .expect("challenge fixture");
        let binding = challenge.binding_digest().expect("binding digest");
        let recorded =
            String::from_utf8(fixture_bytes(&format!("{name}/binding-digest.hex"))).expect("hex");
        assert_eq!(
            hex_encode(&binding),
            recorded.trim(),
            "recomputed binding digest must match the capture's recorded digest"
        );
        let identity: IdentityFile =
            serde_json::from_slice(&fixture_bytes(&format!("{name}/identity.json")))
                .expect("identity fixture");
        assert_eq!(identity.key_length, 32);
        assert_eq!(identity.request["purpose"], "identity");
        assert!(
            identity.request.get("key").is_none(),
            "fixtures carry no private key"
        );
        Self {
            name,
            challenge,
            envelope: fixture_bytes(&format!("{name}/attest-scale-v0.bin")),
            binding,
            identity: Identity {
                public_key: identity.public_key,
                subject_proof_der: hex_decode(&identity.subject_proof_signature_der),
                chain: identity
                    .agent_response_without_key
                    .signature_chain
                    .iter()
                    .map(|link| hex_decode(link))
                    .collect(),
            },
        }
    }

    /// A frozen trusted clock a few seconds into the challenge's window.
    pub fn now_ms(&self) -> u64 {
        self.challenge.issued_at_ms.get() + 5_000
    }
}

pub fn probe_did() -> Probe {
    Probe::load("probe-did")
}

pub fn probe_brc100() -> Probe {
    Probe::load("probe-brc100")
}

#[derive(Debug, Deserialize)]
struct KmsMeta {
    ca_cert: String,
    k256_pubkey: String,
    #[serde(flatten)]
    _rest: serde_json::Map<String, serde_json::Value>,
}

/// KMS pins from the captured `GetMeta`: the CA SPKI is taken from the PEM
/// certificate (never from the evidence), the k256 root from `k256_pubkey`.
pub fn kms_pins() -> KmsPins {
    let meta: KmsMeta = serde_json::from_slice(&fixture_bytes("kms-meta.json")).expect("kms meta");
    let cert = x509_cert::Certificate::from_pem(meta.ca_cert.as_bytes()).expect("kms ca pem");
    let ca_spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("spki der");
    let k256_root: [u8; 33] = hex_decode(&meta.k256_pubkey).try_into().expect("33 bytes");
    assert_eq!(hex_encode(&k256_root), KMS_K256_ROOT);
    KmsPins {
        ca_spki_der,
        k256_root,
        mr_kms: Some(hex_decode(MR_KMS).try_into().expect("32 bytes")),
    }
}

pub fn collateral() -> PinnedCollateral {
    PinnedCollateral::from_json(&fixture_bytes("collateral.json")).expect("pinned collateral")
}

pub fn trust() -> DstackTrust {
    let mut trust = DstackTrust::new(kms_pins());
    trust.min_collateral_issued_ms = COLLATERAL_ISSUED_MS;
    trust
        .allowed_os_image_hashes
        .insert(hex_decode(PROD_OS_IMAGE_HASH).try_into().expect("32"));
    trust
        .allowed_compose_hashes
        .insert(hex_decode(COMPOSE_HASH).try_into().expect("32"));
    trust
}

pub fn attest_verifier() -> DstackAttestV0Verifier {
    DstackAttestV0Verifier::new(trust()).expect("verifier")
}

pub fn subject_key_verifier() -> DstackSubjectKeyV0Verifier {
    DstackSubjectKeyV0Verifier::new()
}

pub fn relation() -> DstackSubjectKeyBrc100Relation {
    DstackSubjectKeyBrc100Relation::new(kms_pins()).expect("relation")
}

pub fn policy() -> DstackBrc100IdentityPolicy {
    DstackSnapshotPlugins::from_snapshot(&snapshot(&probe_brc100().challenge))
        .expect("snapshot plugins")
        .policy
}

pub fn boot_measurements() -> BootMeasurements {
    let info: serde_json::Value =
        serde_json::from_slice(&fixture_bytes("info.json")).expect("info.json");
    let tcb = match &info["tcb_info"] {
        serde_json::Value::String(text) => {
            serde_json::from_str::<serde_json::Value>(text).expect("tcb_info json")
        }
        other => other.clone(),
    };
    let value = |key: &str| {
        tcb[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} measurement"))
            .to_owned()
    };
    BootMeasurements {
        mrtd: value("mrtd"),
        rtmr0: value("rtmr0"),
        rtmr1: value("rtmr1"),
        rtmr2: value("rtmr2"),
    }
}

pub fn policy_artifact() -> DstackPolicyArtifactV1 {
    let kms = kms_pins();
    DstackPolicyArtifactV1 {
        profile: DSTACK_ATTEST_V0_PROVIDER.into(),
        dcap_root: DcapRootV1::IntelSgxRootCaProd,
        min_collateral_issued_ms: U64Decimal::new(&COLLATERAL_ISSUED_MS.to_string())
            .expect("collateral floor"),
        allowed_tcb_statuses: vec!["UpToDate".into()],
        allowed_advisory_ids: vec![],
        allowed_os_image_hashes: vec![PROD_OS_IMAGE_HASH.into()],
        allowed_compose_hashes: vec![COMPOSE_HASH.into()],
        allowed_app_ids: vec![APP_ID.into()],
        kms_ca_spki_der: B64Url::from_bytes(&kms.ca_spki_der),
        kms_k256_root: hex_encode(&kms.k256_root),
        mr_kms: kms.mr_kms.map(|value| hex_encode(&value)),
        allowed_boot_measurements: vec![boot_measurements()],
        allowed_vm_config_digests: vec![],
    }
}

pub fn snapshot(challenge: &Challenge) -> SignedSecuritySnapshot {
    snapshot_with_artifact(challenge, policy_artifact())
}

pub fn snapshot_with_artifact(
    challenge: &Challenge,
    artifact: DstackPolicyArtifactV1,
) -> SignedSecuritySnapshot {
    let provider_artifact = artifact
        .to_provider_artifact("dstack-attest-v0-policy")
        .expect("provider artifact");
    let body = serde_json::json!({
        "securityEpoch": challenge.security_epoch,
        "policyId": challenge.policy_id,
        "policyDigest": challenge.policy_digest,
        "providerArtifacts": [provider_artifact],
        "trustMaterial": {},
        "validFromMs": "0",
        "validUntilMs": u64::MAX.to_string(),
        "signerKeyId": "fixture"
    });
    let trust = Sha256::digest(jcs_bytes(&body).expect("jcs"));
    serde_json::from_value(serde_json::json!({
        "body": body,
        "trustDigest": B64Url::from_bytes(&trust),
        "algorithm": "fixture",
        "signature": "AQ"
    }))
    .expect("snapshot")
}

pub fn parent_component(probe: &Probe) -> EvidenceComponent {
    parent_component_from(&probe.envelope)
}

pub fn parent_component_from(envelope: &[u8]) -> EvidenceComponent {
    EvidenceComponent {
        component_id: PARENT_ID.into(),
        provider: DSTACK_ATTEST_V0_PROVIDER.into(),
        media_type: DSTACK_ATTEST_V0_MEDIA_TYPE.into(),
        evidence: B64Url::from_bytes(envelope),
        endorsements: Some(B64Url::from_bytes(&fixture_bytes("collateral.json"))),
        untrusted_metadata: None,
    }
}

/// The §6.2 child evidence object for a capture, before canonicalization.
pub fn child_evidence_value(identity: &Identity) -> serde_json::Value {
    serde_json::json!({
        "publicKey": identity.public_key,
        "signature": B64Url::from_bytes(&identity.subject_proof_der),
        "keyClaim": B64Url::from_bytes(format!("identity:{}", identity.public_key).as_bytes()),
        "signatureChain": identity
            .chain
            .iter()
            .map(|link| B64Url::from_bytes(link))
            .collect::<Vec<_>>(),
    })
}

pub fn child_component_from_bytes(evidence: &[u8]) -> EvidenceComponent {
    EvidenceComponent {
        component_id: CHILD_ID.into(),
        provider: DSTACK_SUBJECT_KEY_V0_PROVIDER.into(),
        media_type: DSTACK_SUBJECT_KEY_MEDIA_TYPE.into(),
        evidence: B64Url::from_bytes(evidence),
        endorsements: None,
        untrusted_metadata: None,
    }
}

pub fn child_component_from_value(value: &serde_json::Value) -> EvidenceComponent {
    child_component_from_bytes(&jcs_bytes(value).expect("jcs"))
}

pub fn child_component(probe: &Probe) -> EvidenceComponent {
    child_component_from_value(&child_evidence_value(&probe.identity))
}

pub fn edge() -> EvidenceBindingEdge {
    EvidenceBindingEdge {
        parent_component_id: PARENT_ID.into(),
        child_component_id: CHILD_ID.into(),
        relation: DSTACK_SUBJECT_KEY_BRC100_RELATION.into(),
        evidence: None,
    }
}

pub struct FrozenClock(pub u64);

impl Clock for FrozenClock {
    fn now_ms(&self) -> Result<u64, Denial> {
        Ok(self.0)
    }
}

/// Flips one bit of `bytes` at `index`.
pub fn flip_bit(bytes: &mut [u8], index: usize) {
    bytes[index] ^= 0x01;
}

pub fn bundle_components_only(
    probe: &Probe,
    components: Vec<EvidenceComponent>,
) -> binary_attestation_core::EvidenceBundle {
    binary_attestation_core::EvidenceBundle {
        protocol_version: 1,
        challenge_id: probe.challenge.challenge_id.clone(),
        subject: probe.challenge.subject.clone(),
        components,
        binding_edges: None,
    }
}
