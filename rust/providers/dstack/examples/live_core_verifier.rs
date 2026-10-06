//! Issue and verify the snapshot-bound challenge used by the #606 live proof.
//!
//! ```text
//! cargo run -p binary-attestation-dstack --example live_core_verifier -- \
//!   policy collateral.json kms-meta.json policy-pins.json policy-artifact.json
//! cargo run -p binary-attestation-dstack --example live_core_verifier -- \
//!   issue policy-artifact.json <compressed-subject-key> capture-dir
//! curl -fsS -H 'content-type: application/json' \
//!   --data-binary @capture-dir/challenge.json \
//!   https://<cvm>/evidence > capture-dir/evidence-response.json
//! cargo run -p binary-attestation-dstack --example live_core_verifier -- \
//!   verify capture-dir/snapshot.json capture-dir/challenge.json \
//!   capture-dir/evidence-response.json
//! ```
//!
//! Snapshot signatures are fixture publication metadata here: the core's
//! `SecuritySnapshotStore` is the trust boundary for an already-authorized
//! snapshot, exactly as in the hermetic tests. The proof establishes that the
//! snapshot body digest, challenge, live quote, subject-key relation and policy
//! all compose through the real `CoreVerifier` allow path.

use std::{fs, path::Path, sync::Arc, time::SystemTime};

use anyhow::{Context, bail};
use binary_attestation_core::{
    AttestationSubject, B64Url, Challenge, ChallengeStore, CoreVerifier, InMemorySnapshotStore,
    ProviderRegistry, RelationRegistry, SecuritySnapshotBody, SignedSecuritySnapshot, U64Decimal,
    VerificationInput, jcs_bytes,
};
use binary_attestation_dstack::{
    BootMeasurements, DcapRootV1, DstackPolicyArtifactV1, DstackSnapshotPlugins, PinnedCollateral,
};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    der::{DecodePem, Encode},
};

const CHALLENGE_TTL_MS: u64 = 180_000;
const SNAPSHOT_TTL_MS: u64 = 15 * 60_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceResponse {
    public_key: String,
    binding_digest: String,
    bundle: binary_attestation_core::EvidenceBundle,
}

#[derive(Deserialize)]
struct KmsMeta {
    ca_cert: String,
    k256_pubkey: String,
    #[serde(flatten)]
    _rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyPins {
    allowed_tcb_statuses: Vec<String>,
    allowed_advisory_ids: Vec<String>,
    allowed_os_image_hashes: Vec<String>,
    allowed_compose_hashes: Vec<String>,
    allowed_app_ids: Vec<String>,
    mr_kms: Option<String>,
    allowed_boot_measurements: Vec<BootMeasurements>,
    #[serde(default)]
    allowed_vm_config_digests: Vec<String>,
}

fn now_ms() -> anyhow::Result<u64> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_millis()
        .try_into()
        .context("system clock does not fit u64")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("serialize proof artifact")?;
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn subject(value: String) -> AttestationSubject {
    AttestationSubject {
        kind: "brc100-public-key".into(),
        value,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn build_policy(
    collateral_path: &Path,
    kms_meta_path: &Path,
    pins_path: &Path,
    output_path: &Path,
) -> anyhow::Result<()> {
    let collateral =
        fs::read(collateral_path).with_context(|| format!("read {}", collateral_path.display()))?;
    PinnedCollateral::from_json(&collateral).context("validate pinned collateral")?;
    let kms: KmsMeta = read_json(kms_meta_path)?;
    let pins: PolicyPins = read_json(pins_path)?;
    let cert = Certificate::from_pem(kms.ca_cert.as_bytes()).context("parse KMS CA PEM")?;
    let ca_spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("encode KMS CA SPKI")?;

    let policy = DstackPolicyArtifactV1 {
        profile: "dstack-attest-v0".into(),
        dcap_root: DcapRootV1::IntelSgxRootCaProd,
        collateral_json: vec![B64Url::from_bytes(&collateral)],
        allowed_tcb_statuses: pins.allowed_tcb_statuses,
        allowed_advisory_ids: pins.allowed_advisory_ids,
        allowed_os_image_hashes: pins.allowed_os_image_hashes,
        allowed_compose_hashes: pins.allowed_compose_hashes,
        allowed_app_ids: pins.allowed_app_ids,
        kms_ca_spki_der: B64Url::from_bytes(&ca_spki_der),
        kms_k256_root: kms.k256_pubkey,
        mr_kms: pins.mr_kms,
        allowed_boot_measurements: pins.allowed_boot_measurements,
        allowed_vm_config_digests: pins.allowed_vm_config_digests,
    };
    policy
        .to_provider_artifact("dstack-attest-v0-policy")
        .context("canonical provider artifact")?;
    write_json(output_path, &policy)
}

fn issue(policy_path: &Path, subject_key: String, out_dir: &Path) -> anyhow::Result<()> {
    let policy: DstackPolicyArtifactV1 = read_json(policy_path)?;
    let provider_artifact = policy
        .to_provider_artifact("dstack-attest-v0-policy")
        .context("canonical provider artifact")?;
    let now = now_ms()?;
    let epoch = U64Decimal::new(&now.to_string()).context("security epoch")?;
    let policy_digest = provider_artifact.digest.clone();
    let body = SecuritySnapshotBody {
        security_epoch: epoch,
        policy_id: "dstack-live-core-verifier-v1".into(),
        policy_digest: policy_digest.clone(),
        provider_artifacts: vec![provider_artifact],
        trust_material: serde_json::Map::new(),
        valid_from_ms: U64Decimal::new(&now.saturating_sub(1_000).to_string())?,
        valid_until_ms: U64Decimal::new(&(now + SNAPSHOT_TTL_MS).to_string())?,
        signer_key_id: "local-live-proof-publisher".into(),
    };
    let trust_digest = B64Url::from_bytes(&Sha256::digest(jcs_bytes(&body)?));
    let snapshot = SignedSecuritySnapshot {
        body,
        trust_digest: trust_digest.clone(),
        algorithm: "local-live-proof-v1".into(),
        signature: B64Url::from_bytes(&[1]),
    };
    snapshot.validate().context("snapshot")?;

    let mut challenge_id = [0u8; 16];
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut challenge_id);
    OsRng.fill_bytes(&mut nonce);
    let mut context = Sha256::new();
    context.update(b"bcap1-live-core-verifier-v1\0");
    context.update(subject_key.as_bytes());
    context.update(policy_digest.bytes::<32>()?);
    let challenge = Challenge {
        protocol_version: 1,
        challenge_id: B64Url::from_bytes(&challenge_id),
        nonce: B64Url::from_bytes(&nonce),
        subject: subject(subject_key),
        audience: "urn:binary:bcap1:dstack-live-core-verifier".into(),
        context: "urn:binary:bcap1:dstack-live-core-verifier:quote".into(),
        context_digest: B64Url::from_bytes(&context.finalize()),
        policy_id: snapshot.body.policy_id.clone(),
        policy_digest,
        security_epoch: epoch,
        trust_digest,
        issued_at_ms: U64Decimal::new(&now.to_string())?,
        expires_at_ms: U64Decimal::new(&(now + CHALLENGE_TTL_MS).to_string())?,
    };
    challenge.validate().context("challenge")?;

    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    write_json(&out_dir.join("policy-artifact.json"), &policy)?;
    write_json(&out_dir.join("snapshot.json"), &snapshot)?;
    write_json(&out_dir.join("challenge.json"), &challenge)?;
    println!(
        "{}",
        serde_json::json!({
            "challengeId": challenge.challenge_id,
            "subject": challenge.subject,
            "trustDigest": snapshot.trust_digest,
            "policyDigest": snapshot.body.policy_digest,
            "snapshot": out_dir.join("snapshot.json"),
            "challenge": out_dir.join("challenge.json")
        })
    );
    Ok(())
}

fn verify(snapshot_path: &Path, challenge_path: &Path, response_path: &Path) -> anyhow::Result<()> {
    let snapshot: SignedSecuritySnapshot = read_json(snapshot_path)?;
    let challenge: Challenge = read_json(challenge_path)?;
    let response: EvidenceResponse = read_json(response_path)?;
    snapshot.validate().context("snapshot")?;
    challenge.validate().context("challenge")?;
    if response.public_key != challenge.subject.value
        || response.bundle.subject != challenge.subject
    {
        bail!("response subject does not equal the issued BRC-100 subject");
    }
    let binding = challenge.binding_digest().context("challenge binding")?;
    if response.binding_digest != hex_encode(&binding) {
        bail!("response binding digest does not equal the issued challenge");
    }

    let plugins = DstackSnapshotPlugins::from_snapshot(&snapshot).context("snapshot plugins")?;
    let providers = Arc::new(ProviderRegistry::new());
    providers
        .register(Arc::new(plugins.parent))
        .context("register dstack parent")?;
    providers
        .register(Arc::new(plugins.child))
        .context("register subject-key child")?;
    let relations = Arc::new(RelationRegistry::new());
    relations
        .register(Arc::new(plugins.relation))
        .context("register subject-key relation")?;
    let snapshots = Arc::new(InMemorySnapshotStore::new());
    snapshots.publish(snapshot).context("publish snapshot")?;
    let challenges = Arc::new(ChallengeStore::default());
    challenges
        .issue(challenge.clone(), now_ms()?)
        .context("issue challenge")?;
    let core = CoreVerifier::new(
        challenges,
        snapshots,
        providers,
        relations,
        Arc::new(plugins.policy),
    );
    let claims = core
        .verify(VerificationInput {
            authenticated_subject: &challenge.subject,
            bundle: &response.bundle,
            transport_context_digest: &challenge.context_digest,
        })
        .context("CoreVerifier denied live evidence")?;
    println!(
        "{}",
        serde_json::json!({
            "decision": "allowed",
            "challengeId": challenge.challenge_id,
            "subject": claims.subject,
            "subjectBinding": claims.subject_binding,
            "bindingDigest": claims.binding_digest,
            "validUntilMs": claims.valid_until_ms,
            "components": claims.components
        })
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, collateral, kms_meta, pins, output] if command == "policy" => build_policy(
            Path::new(collateral),
            Path::new(kms_meta),
            Path::new(pins),
            Path::new(output),
        ),
        [command, policy, subject, out_dir] if command == "issue" => issue(
            Path::new(policy),
            subject.to_string_lossy().into_owned(),
            Path::new(out_dir),
        ),
        [command, snapshot, challenge, response] if command == "verify" => verify(
            Path::new(snapshot),
            Path::new(challenge),
            Path::new(response),
        ),
        _ => bail!(
            "usage: live_core_verifier policy <collateral.json> <kms-meta.json> \
             <pins.json> <output.json> | \
             issue <policy.json> <subject-key> <out-dir> | \
             verify <snapshot.json> <challenge.json> <evidence-response.json>"
        ),
    }
}
