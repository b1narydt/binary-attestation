use std::sync::Arc;

use binary_attestation_core::{
    AuthenticatedAttestationChannel, B64Url, BindingRelationVerifier, Challenge, ChallengeState,
    ChallengeStore, Denial, EvidenceBindingEdge, EvidenceBundle, EvidenceComponent,
    EvidenceVerifier, InMemorySnapshotStore, MAX_BINDING_EDGE_EVIDENCE, MAX_BUNDLE_BYTES,
    MAX_COMPONENT_EVIDENCE, PolicyDecision, ProviderRegistry, RelationRegistry,
    SecuritySnapshotStore, SignedSecuritySnapshot, TransportMessage, VerifiedComponent,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn challenge() -> Challenge {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/bcap1-transcript.json"))
            .expect("vectors");
    serde_json::from_value(vectors["valid"][0]["input"].clone()).expect("challenge")
}

fn snapshot_for(challenge: &mut Challenge, epoch: u64) -> SignedSecuritySnapshot {
    challenge.security_epoch = serde_json::from_value(json!(epoch.to_string())).expect("epoch");
    let body = json!({
        "securityEpoch": epoch.to_string(), "policyId": challenge.policy_id,
        "policyDigest": challenge.policy_digest, "providerArtifacts": [], "trustMaterial": {},
        "validFromMs": "0", "validUntilMs": "100", "signerKeyId": "fixture"
    });
    challenge.trust_digest = B64Url::from_bytes(&Sha256::digest(
        binary_attestation_core::jcs_bytes(&body).expect("jcs"),
    ));
    serde_json::from_value(json!({
        "body": body, "trustDigest": challenge.trust_digest, "algorithm": "fixture", "signature": "AQ"
    }))
    .expect("snapshot")
}

fn two_component_bundle(edge_evidence: Vec<u8>, edges: usize) -> EvidenceBundle {
    let challenge = challenge();
    EvidenceBundle {
        protocol_version: 1,
        challenge_id: challenge.challenge_id,
        subject: challenge.subject,
        components: ["parent", "child"]
            .into_iter()
            .map(|id| EvidenceComponent {
                component_id: id.into(),
                provider: "fixture-v1".into(),
                media_type: "application/fixture".into(),
                evidence: B64Url::from_bytes(&[1]),
                endorsements: None,
                untrusted_metadata: None,
            })
            .collect(),
        binding_edges: Some(
            (0..edges)
                .map(|_| EvidenceBindingEdge {
                    parent_component_id: "parent".into(),
                    child_component_id: "child".into(),
                    relation: "fixture-links-v1".into(),
                    evidence: Some(B64Url::from_bytes(&edge_evidence)),
                })
                .collect(),
        ),
    }
}

fn bundle_with_distinct_edge_endpoints(edge_evidence: Vec<u8>, edges: usize) -> EvidenceBundle {
    let challenge = challenge();
    let mut component_ids = vec!["root".to_owned()];
    component_ids.extend((0..edges).map(|index| format!("child-{index}")));
    EvidenceBundle {
        protocol_version: 1,
        challenge_id: challenge.challenge_id,
        subject: challenge.subject,
        components: component_ids
            .iter()
            .map(|id| EvidenceComponent {
                component_id: id.clone(),
                provider: "fixture-v1".into(),
                media_type: "application/fixture".into(),
                evidence: B64Url::from_bytes(&[1]),
                endorsements: None,
                untrusted_metadata: None,
            })
            .collect(),
        binding_edges: Some(
            (0..edges)
                .map(|index| EvidenceBindingEdge {
                    parent_component_id: "root".into(),
                    child_component_id: format!("child-{index}"),
                    relation: "fixture-links-v1".into(),
                    evidence: Some(B64Url::from_bytes(&edge_evidence)),
                })
                .collect(),
        ),
    }
}

#[test]
fn edge_evidence_has_own_and_total_bundle_resource_limits() {
    assert!(matches!(
        two_component_bundle(vec![0; MAX_BINDING_EDGE_EVIDENCE + 1], 1).validate(),
        Err(Denial::ResourceLimit)
    ));
    assert!(matches!(
        bundle_with_distinct_edge_endpoints(vec![0; MAX_BINDING_EDGE_EVIDENCE], 8).validate(),
        Err(Denial::ResourceLimit)
    ));
}

fn zero_base64url(decoded_len: usize) -> String {
    let mut encoded = "AAAA".repeat(decoded_len / 3);
    match decoded_len % 3 {
        1 => encoded.push_str("AA"),
        2 => encoded.push_str("AAA"),
        _ => {}
    }
    encoded
}

#[test]
fn base64url_tail_bits_and_oversized_encoded_inputs_refuse_without_decode() {
    // These decode to the same bytes as AA/AAA but have non-zero unused tail
    // bits, so canonical unpadded base64url must reject them syntactically.
    assert!(matches!(B64Url::new("AB"), Err(Denial::Malformed)));
    assert!(matches!(B64Url::new("AAB"), Err(Denial::Malformed)));
    assert!(B64Url::new("AA").is_ok());
    assert!(B64Url::new("AAA").is_ok());

    let oversized_component =
        B64Url::new(zero_base64url(MAX_COMPONENT_EVIDENCE + 1)).expect("syntactic only");
    let mut bundle = two_component_bundle(vec![0], 0);
    bundle.components[0].evidence = oversized_component;
    assert!(matches!(bundle.validate(), Err(Denial::ResourceLimit)));

    let subject = binary_attestation_core::AttestationSubject {
        kind: "did".into(),
        value: "peer".into(),
    };
    let message = TransportMessage {
        protocol_version: 1,
        message_type: binary_attestation_core::MessageType::Challenge,
        message_id: B64Url::from_bytes(&[0; 16]),
        sender: subject.clone(),
        recipient: subject.clone(),
        context_digest: B64Url::from_bytes(&[0; 32]),
        payload_encoding: "rfc8785-jcs".into(),
        payload: B64Url::new(zero_base64url(MAX_BUNDLE_BYTES + 1)).expect("syntactic only"),
        payload_digest: B64Url::from_bytes(&[0; 32]),
    };
    assert!(matches!(
        message.decode(subject.clone(), &subject),
        Err(Denial::ResourceLimit)
    ));
}

struct NamedProvider(&'static str);
impl EvidenceVerifier for NamedProvider {
    fn provider(&self) -> &'static str {
        self.0
    }
    fn verify(
        &self,
        _: &EvidenceComponent,
        _: [u8; 64],
        _: u64,
    ) -> Result<VerifiedComponent, Denial> {
        Err(Denial::InternalError)
    }
}
struct NamedRelation(&'static str);
impl BindingRelationVerifier for NamedRelation {
    fn relation(&self) -> &'static str {
        self.0
    }
    fn verify(
        &self,
        _: &VerifiedComponent,
        _: &VerifiedComponent,
        _: &EvidenceBindingEdge,
        _: [u8; 64],
        _: u64,
    ) -> Result<(), Denial> {
        Err(Denial::InternalError)
    }
}

#[test]
fn duplicate_registry_registration_preserves_original_plugin() {
    let providers = ProviderRegistry::new();
    let original: Arc<dyn EvidenceVerifier> = Arc::new(NamedProvider("fixture-v1"));
    providers.register(original.clone()).expect("original");
    assert!(matches!(
        providers.register(Arc::new(NamedProvider("fixture-v1"))),
        Err(Denial::Malformed)
    ));
    assert!(Arc::ptr_eq(
        &original,
        &providers.get("fixture-v1").expect("original remains")
    ));

    let relations = RelationRegistry::new();
    let original: Arc<dyn BindingRelationVerifier> = Arc::new(NamedRelation("fixture-links-v1"));
    relations.register(original.clone()).expect("original");
    assert!(matches!(
        relations.register(Arc::new(NamedRelation("fixture-links-v1"))),
        Err(Denial::Malformed)
    ));
    assert!(Arc::ptr_eq(
        &original,
        &relations.get("fixture-links-v1").expect("original remains")
    ));
}

#[test]
fn terminal_fence_has_one_order_with_epoch_publication() {
    // allow first: the fence commits before publication, so the later update
    // cannot retroactively undo that recorded terminal decision.
    let mut first = challenge();
    let initial = snapshot_for(&mut first, 0);
    let mut update_challenge = first.clone();
    let update = snapshot_for(&mut update_challenge, 1);
    let snapshots = InMemorySnapshotStore::new();
    snapshots.publish(initial).expect("initial");
    let local = ChallengeStore::new(1, 2);
    local.issue(first.clone(), 1).expect("issue");
    local
        .begin(
            first.challenge_id.as_str(),
            &first.subject,
            &first.subject,
            1,
        )
        .expect("claim");
    snapshots
        .terminal_fence(&first, 1)
        .expect("allow-first fence");
    snapshots.publish(update).expect("later update");
    local
        .finish(first.challenge_id.as_str(), Ok(()), 1)
        .expect("mirror commit");
    assert_eq!(
        local.state(first.challenge_id.as_str(), 1),
        Ok(ChallengeState::ConsumedAllow)
    );

    // update first: the fence rejects and the local cache is terminal-denied;
    // it cannot retain an allow state after shared-fence failure.
    let mut old = challenge();
    let initial = snapshot_for(&mut old, 0);
    let mut update_challenge = old.clone();
    let update = snapshot_for(&mut update_challenge, 1);
    let snapshots = InMemorySnapshotStore::new();
    snapshots.publish(initial).expect("initial");
    let local = ChallengeStore::new(1, 2);
    local.issue(old.clone(), 1).expect("issue");
    local
        .begin(old.challenge_id.as_str(), &old.subject, &old.subject, 1)
        .expect("claim");
    snapshots.publish(update).expect("update-first");
    let denial = snapshots
        .terminal_fence(&old, 1)
        .expect_err("stale epoch refuses");
    assert_eq!(denial, Denial::SecurityEpochChanged);
    assert_eq!(
        local.finish(old.challenge_id.as_str(), Err(denial), 1),
        Err(Denial::SecurityEpochChanged)
    );
    assert_eq!(
        local.state(old.challenge_id.as_str(), 1),
        Ok(ChallengeState::ConsumedDeny(Denial::SecurityEpochChanged))
    );
}

#[test]
fn terminal_fence_refuses_at_exclusive_challenge_expiry() {
    let mut challenge = challenge(); // fixture expires at 2
    let snapshot = snapshot_for(&mut challenge, 0);
    let snapshots = InMemorySnapshotStore::new();
    snapshots.publish(snapshot).expect("initial");
    assert_eq!(
        snapshots.terminal_fence(&challenge, 2),
        Err(Denial::ChallengeExpired)
    );
}

#[test]
fn policy_valid_until_is_exclusive() {
    let decision = PolicyDecision {
        subject_binding: "fixture-proof".into(),
        valid_until_ms: 1,
    };
    assert!(matches!(
        decision.claims(&challenge(), vec![], 1, 1),
        Err(Denial::PolicyMismatch)
    ));
}

fn _assert_transport_contract<T: AuthenticatedAttestationChannel>() {}
