//! `DstackBrc100IdentityPolicy`: one dstack parent, one subject-key child,
//! the challenge subject is the child's key, plus measurement allowlists.

mod common;

use std::collections::BTreeSet;

use binary_attestation_core::{
    B64Url, BindingRelationVerifier, Challenge, Denial, EvidenceVerifier, PolicyEvaluator,
    SignedSecuritySnapshot, VerifiedComponent, jcs_bytes,
};
use binary_attestation_dstack::{
    BootMeasurements, DSTACK_SUBJECT_KEY_BRC100_RELATION, DstackBrc100IdentityPolicy,
    scale::LegacyAttestationV0,
};
use common::*;
use serde_json::json;
use sha2::{Digest, Sha256};

fn verified_claims(probe: &Probe) -> Vec<VerifiedComponent> {
    let parent = attest_verifier()
        .verify(&parent_component(probe), probe.binding, probe.now_ms())
        .expect("parent");
    let child = subject_key_verifier()
        .verify(&child_component(probe), probe.binding, probe.now_ms())
        .expect("child");
    relation()
        .verify(&parent, &child, &edge(), probe.binding, probe.now_ms())
        .expect("relation");
    vec![parent, child]
}

/// A snapshot the policy can see. The live probe challenges do not commit to
/// a snapshot body (see `pipeline.rs`), so this one is only policy input.
fn snapshot(challenge: &Challenge) -> SignedSecuritySnapshot {
    let body = json!({
        "securityEpoch": "0", "policyId": challenge.policy_id, "policyDigest": challenge.policy_digest,
        "providerArtifacts": [], "trustMaterial": {"dstack": {"profile": "dstack-attest-v0"}},
        "validFromMs": "0", "validUntilMs": u64::MAX.to_string(), "signerKeyId": "fixture"
    });
    let trust = Sha256::digest(jcs_bytes(&body).expect("jcs"));
    serde_json::from_value(json!({
        "body": body, "trustDigest": B64Url::from_bytes(&trust), "algorithm": "fixture", "signature": "AQ"
    }))
    .expect("snapshot")
}

/// Evaluates and flattens the decision so denials compare structurally.
fn evaluate(
    policy: &DstackBrc100IdentityPolicy,
    probe: &Probe,
    claims: &[VerifiedComponent],
) -> Result<(String, u64), Denial> {
    policy
        .evaluate(
            &probe.challenge,
            claims,
            &snapshot(&probe.challenge),
            probe.now_ms(),
        )
        .map(|decision| (decision.subject_binding, decision.valid_until_ms))
}

#[test]
fn brc100_probe_is_allowed_with_the_subject_key_relation_as_subject_binding() {
    let probe = probe_brc100();
    let claims = verified_claims(&probe);
    let (subject_binding, valid_until_ms) = evaluate(&policy(), &probe, &claims).expect("allowed");
    assert_eq!(subject_binding, DSTACK_SUBJECT_KEY_BRC100_RELATION);
    assert_eq!(valid_until_ms, COLLATERAL_EARLIEST_EXPIRY_MS);
    let decision = policy()
        .evaluate(
            &probe.challenge,
            &claims,
            &snapshot(&probe.challenge),
            probe.now_ms(),
        )
        .expect("allowed");
    let verified = decision
        .claims(
            &probe.challenge,
            claims,
            probe.now_ms(),
            COLLATERAL_EARLIEST_EXPIRY_MS,
        )
        .expect("claims");
    assert_eq!(verified.subject.value, probe.identity.public_key);
}

#[test]
fn did_probe_subject_is_refused_even_though_evidence_and_relation_verify() {
    // The first live capture's challenge subject is `{type:"did"}`; the policy
    // requires the attested BRC-100 key as subject, so it must refuse without
    // any change to the (verified) evidence.
    let probe = probe_did();
    let claims = verified_claims(&probe);
    assert_eq!(probe.challenge.subject.kind, "did");
    assert_eq!(
        evaluate(&policy(), &probe, &claims),
        Err(Denial::SubjectMismatch)
    );
}

#[test]
fn subject_value_must_equal_the_attested_public_key() {
    let mut probe = probe_brc100();
    let claims = verified_claims(&probe);
    probe.challenge.subject.value = KMS_K256_ROOT.into();
    assert_eq!(
        evaluate(&policy(), &probe, &claims),
        Err(Denial::SubjectMismatch)
    );
}

#[test]
fn exactly_one_parent_and_one_child_are_required() {
    let probe = probe_brc100();
    let claims = verified_claims(&probe);
    assert_eq!(
        evaluate(&policy(), &probe, &claims[..1]),
        Err(Denial::ComponentMissing)
    );
    assert_eq!(
        evaluate(&policy(), &probe, &claims[1..]),
        Err(Denial::ComponentMissing)
    );
    assert_eq!(
        evaluate(&policy(), &probe, &[]),
        Err(Denial::ComponentMissing)
    );
    let mut three = claims.clone();
    let mut extra = claims[1].clone();
    extra.component_id = "second-key".into();
    three.push(extra);
    assert_eq!(
        evaluate(&policy(), &probe, &three),
        Err(Denial::PolicyMismatch)
    );
}

#[test]
fn mock_or_foreign_provider_claims_are_unsupported_provider() {
    let probe = probe_brc100();
    let mut claims = verified_claims(&probe);
    claims[0].provider = "mock-dstack-attest-v0".into();
    assert_eq!(
        evaluate(&policy(), &probe, &claims),
        Err(Denial::UnsupportedProvider)
    );
    let mut claims = verified_claims(&probe);
    claims[0]
        .platform
        .insert("profile".into(), json!("dstack-v1"));
    assert_eq!(
        evaluate(&policy(), &probe, &claims),
        Err(Denial::UnsupportedProvider)
    );
}

#[test]
fn os_image_compose_and_app_id_allowlists_are_enforced() {
    let probe = probe_brc100();
    let claims = verified_claims(&probe);
    let dev_only = DstackBrc100IdentityPolicy::new(BTreeSet::from([DEV_OS_IMAGE_HASH.to_owned()]));
    assert_eq!(
        evaluate(&dev_only, &probe, &claims),
        Err(Denial::MeasurementMismatch)
    );
    let mut policy = policy();
    policy.allowed_compose_hashes = Some(BTreeSet::from(["00".repeat(32)]));
    assert_eq!(
        evaluate(&policy, &probe, &claims),
        Err(Denial::MeasurementMismatch)
    );
    let mut policy = common::policy();
    policy.allowed_app_ids = Some(BTreeSet::from(["00".repeat(20)]));
    assert_eq!(
        evaluate(&policy, &probe, &claims),
        Err(Denial::MeasurementMismatch)
    );
    let mut policy = common::policy();
    policy.allowed_compose_hashes = Some(BTreeSet::from([COMPOSE_HASH.to_owned()]));
    policy.allowed_app_ids = Some(BTreeSet::from([APP_ID.to_owned()]));
    evaluate(&policy, &probe, &claims).expect("matching allowlists");
}

#[test]
fn boot_measurement_pins_are_enforced() {
    let probe = probe_brc100();
    let claims = verified_claims(&probe);
    let live = BootMeasurements {
        mrtd: claims[0].measurements["mrtd"].as_str().unwrap().into(),
        rtmr0: claims[0].measurements["rtmr0"].as_str().unwrap().into(),
        rtmr1: claims[0].measurements["rtmr1"].as_str().unwrap().into(),
        rtmr2: claims[0].measurements["rtmr2"].as_str().unwrap().into(),
    };
    let mut policy = policy();
    policy.allowed_boot_measurements = Some(BTreeSet::from([live.clone()]));
    evaluate(&policy, &probe, &claims).expect("live boot measurements");
    let mut other = live;
    other.rtmr1 = "00".repeat(48);
    policy.allowed_boot_measurements = Some(BTreeSet::from([other]));
    assert_eq!(
        evaluate(&policy, &probe, &claims),
        Err(Denial::MeasurementMismatch)
    );
}

#[test]
fn vm_config_digest_pin_refuses_an_unmeasured_config_tamper() {
    let probe = probe_brc100();
    let claims = verified_claims(&probe);
    let digest = claims[0].measurements["vm_config_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut policy = policy();
    policy.allowed_vm_config_digests = Some(BTreeSet::from([digest]));
    evaluate(&policy, &probe, &claims).expect("live config");

    let mut envelope = LegacyAttestationV0::decode(&probe.envelope).expect("decode");
    envelope.config = envelope
        .config
        .replacen("\"cpu_count\":1", "\"cpu_count\":2", 1);
    let tampered_parent = attest_verifier()
        .verify(
            &parent_component_from(&envelope.encode()),
            probe.binding,
            probe.now_ms(),
        )
        .expect("config is not quote-measured on 0.5.x");
    let claims = vec![tampered_parent, claims[1].clone()];
    assert_eq!(
        evaluate(&policy, &probe, &claims),
        Err(Denial::MeasurementMismatch)
    );
}

#[test]
fn policy_refuses_an_empty_os_image_allowlist() {
    let probe = probe_brc100();
    let claims = verified_claims(&probe);
    let policy = DstackBrc100IdentityPolicy::new(BTreeSet::new());
    assert_eq!(
        evaluate(&policy, &probe, &claims),
        Err(Denial::PolicyUnknown)
    );
}
