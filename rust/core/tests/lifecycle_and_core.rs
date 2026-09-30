use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};

use binary_attestation_core::{
    B64Url, BindingRelationVerifier, Challenge, ChallengeState, ChallengeStore, Clock,
    CoreVerifier, Denial, EvidenceBindingEdge, EvidenceBundle, EvidenceComponent, EvidenceVerifier,
    InMemorySnapshotStore, PolicyDecision, PolicyEvaluator, ProviderRegistry, RelationRegistry,
    SignedSecuritySnapshot, VerificationInput, VerifiedComponent,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn base_challenge() -> Challenge {
    serde_json::from_str(include_str!("../../../vectors/bcap1-transcript.json"))
        .ok()
        .and_then(|value: serde_json::Value| {
            serde_json::from_value(value["valid"][0]["input"].clone()).ok()
        })
        .expect("challenge fixture")
}

#[test]
fn challenge_is_single_use_across_races_and_expiry() {
    let challenge = base_challenge();
    let store = Arc::new(ChallengeStore::new(4, 10));
    store.issue(challenge.clone(), 0).expect("issue");
    let gate = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = Arc::clone(&store);
        let challenge = challenge.clone();
        let gate = Arc::clone(&gate);
        handles.push(thread::spawn(move || {
            gate.wait();
            store.begin(
                challenge.challenge_id.as_str(),
                &challenge.subject,
                &challenge.subject,
                0,
            )
        }));
    }
    gate.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .copied()
            .collect::<Vec<_>>(),
        vec![Denial::ChallengeUsed]
    );
    store
        .finish(challenge.challenge_id.as_str(), Ok(()), 1)
        .expect("finish");

    let later = base_challenge();
    let store = ChallengeStore::new(4, 10);
    store.issue(later.clone(), 0).expect("issue");
    store
        .begin(
            later.challenge_id.as_str(),
            &later.subject,
            &later.subject,
            0,
        )
        .expect("claim");
    assert!(matches!(
        store.begin(
            later.challenge_id.as_str(),
            &later.subject,
            &later.subject,
            2
        ),
        Err(Denial::ChallengeUsed)
    ));
    assert_eq!(
        store.finish(later.challenge_id.as_str(), Ok(()), 2),
        Err(Denial::ChallengeExpired)
    );
    assert_eq!(
        store.state(later.challenge_id.as_str(), 2),
        Ok(ChallengeState::ConsumedDeny(Denial::ChallengeExpired))
    );
}

#[test]
fn limits_release_capacity_after_terminal_state_and_future_issue_refuses() {
    let first = base_challenge();
    let mut second = first.clone();
    second.challenge_id = B64Url::from_bytes(&[1; 16]);
    let store = ChallengeStore::new(1, 1);
    store.issue(first.clone(), 0).expect("first");
    assert_eq!(store.issue(second.clone(), 0), Err(Denial::ResourceLimit));
    store
        .begin(
            first.challenge_id.as_str(),
            &first.subject,
            &first.subject,
            0,
        )
        .expect("begin");
    store
        .finish(
            first.challenge_id.as_str(),
            Err(Denial::SignatureInvalid),
            1,
        )
        .expect_err("deny is surfaced");
    store
        .issue(second, 0)
        .expect("terminal entry no longer consumes quota");

    let mut future = base_challenge();
    future.issued_at_ms = serde_json::from_str("\"1\"").expect("u64");
    assert_eq!(
        ChallengeStore::new(1, 1).issue(future, 0),
        Err(Denial::Malformed)
    );
    assert!(matches!(
        ChallengeStore::try_new(9, 1),
        Err(Denial::ResourceLimit)
    ));
}

#[derive(Default)]
struct ManualClock(AtomicU64);
impl ManualClock {
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
impl Clock for ManualClock {
    fn now_ms(&self) -> Result<u64, Denial> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct FixtureVerifier {
    clock: Option<Arc<ManualClock>>,
}
impl EvidenceVerifier for FixtureVerifier {
    fn provider(&self) -> &'static str {
        "fixture-v1"
    }
    fn verify(
        &self,
        component: &EvidenceComponent,
        expected: [u8; 64],
        _now: u64,
    ) -> Result<VerifiedComponent, Denial> {
        if let Some(clock) = &self.clock {
            clock.set(20);
        }
        Ok(VerifiedComponent {
            component_id: component.component_id.clone(),
            provider: component.provider.clone(),
            evidence_digest: B64Url::from_bytes(&Sha256::digest(component.evidence.decode())),
            binding_digest: if component.component_id == "parent" {
                B64Url::from_bytes(&expected)
            } else {
                B64Url::from_bytes(&[0; 64])
            },
            platform: Default::default(),
            measurements: Default::default(),
            tcb: Default::default(),
            advisories: vec![],
            valid_until_ms: serde_json::from_str("\"100\"").expect("u64"),
        })
    }
}
struct FixtureRelation;
impl BindingRelationVerifier for FixtureRelation {
    fn relation(&self) -> &'static str {
        "fixture-links-v1"
    }
    fn verify(
        &self,
        _parent: &VerifiedComponent,
        _child: &VerifiedComponent,
        _edge: &EvidenceBindingEdge,
        _expected: [u8; 64],
        _now: u64,
    ) -> Result<(), Denial> {
        Ok(())
    }
}
struct AllowPolicy;
impl PolicyEvaluator for AllowPolicy {
    fn evaluate(
        &self,
        _challenge: &Challenge,
        _claims: &[VerifiedComponent],
        _snapshot: &SignedSecuritySnapshot,
        _now: u64,
    ) -> Result<PolicyDecision, Denial> {
        Ok(PolicyDecision {
            subject_binding: "fixture-subject-proof-v1".into(),
            valid_until_ms: 100,
        })
    }
}

fn snapshot_and_challenge(expires: u64) -> (SignedSecuritySnapshot, Challenge) {
    let mut challenge = base_challenge();
    challenge.expires_at_ms = serde_json::from_value(json!(expires.to_string())).expect("u64");
    let mut body = json!({
        "securityEpoch": "0", "policyId": challenge.policy_id, "policyDigest": challenge.policy_digest,
        "providerArtifacts": [], "trustMaterial": {}, "validFromMs": "0", "validUntilMs": "100", "signerKeyId": "fixture"
    });
    let trust = Sha256::digest(binary_attestation_core::jcs_bytes(&body).expect("jcs"));
    challenge.trust_digest = B64Url::from_bytes(&trust);
    let signed = json!({"body": body.take(), "trustDigest": challenge.trust_digest, "algorithm": "fixture", "signature": "AQ"});
    (serde_json::from_value(signed).expect("snapshot"), challenge)
}

fn bundle(challenge: &Challenge, edge: bool) -> EvidenceBundle {
    EvidenceBundle {
        protocol_version: 1,
        challenge_id: challenge.challenge_id.clone(),
        subject: challenge.subject.clone(),
        components: vec![
            EvidenceComponent {
                component_id: "parent".into(),
                provider: "fixture-v1".into(),
                media_type: "application/fixture".into(),
                evidence: B64Url::from_bytes(&[1]),
                endorsements: None,
                untrusted_metadata: None,
            },
            EvidenceComponent {
                component_id: "child".into(),
                provider: "fixture-v1".into(),
                media_type: "application/fixture".into(),
                evidence: B64Url::from_bytes(&[2]),
                endorsements: None,
                untrusted_metadata: None,
            },
        ],
        binding_edges: edge.then(|| {
            vec![EvidenceBindingEdge {
                parent_component_id: "parent".into(),
                child_component_id: "child".into(),
                relation: "fixture-links-v1".into(),
                evidence: None,
            }]
        }),
    }
}

fn core(
    snapshot: SignedSecuritySnapshot,
    clock: Arc<ManualClock>,
) -> (CoreVerifier, Arc<ChallengeStore>) {
    let snapshots = Arc::new(InMemorySnapshotStore::new());
    snapshots.publish(snapshot).expect("publish");
    let challenges = Arc::new(ChallengeStore::new(4, 10));
    let providers = Arc::new(ProviderRegistry::new());
    providers
        .register(Arc::new(FixtureVerifier {
            clock: Some(clock.clone()),
        }))
        .expect("provider");
    let relations = Arc::new(RelationRegistry::new());
    relations
        .register(Arc::new(FixtureRelation))
        .expect("relation");
    (
        CoreVerifier::with_clock(
            challenges.clone(),
            snapshots,
            providers,
            relations,
            Arc::new(AllowPolicy),
            clock,
        ),
        challenges,
    )
}

#[test]
fn indirect_relation_is_valid_but_unbound_child_refuses() {
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    let (snapshot, challenge) = snapshot_and_challenge(100);
    let (verifier, store) = core(snapshot, clock.clone());
    store.issue(challenge.clone(), 1).expect("issue");
    let accepted = verifier.verify(VerificationInput {
        authenticated_subject: &challenge.subject,
        bundle: &bundle(&challenge, true),
        transport_context_digest: &challenge.context_digest,
    });
    assert!(accepted.is_ok(), "{accepted:?}");

    let (snapshot, challenge) = snapshot_and_challenge(20);
    let (core, store) = core(snapshot, clock);
    store.issue(challenge.clone(), 1).expect("issue");
    let denied = core.verify_at(
        VerificationInput {
            authenticated_subject: &challenge.subject,
            bundle: &bundle(&challenge, false),
            transport_context_digest: &challenge.context_digest,
        },
        1,
    );
    assert!(matches!(denied, Err(Denial::ComponentUnbound)));
}

#[test]
fn verification_rechecks_trusted_clock_before_allow() {
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    let (snapshot, challenge) = snapshot_and_challenge(2);
    let (verifier, store) = core(snapshot, clock);
    store.issue(challenge.clone(), 1).expect("issue");
    let result = verifier.verify(VerificationInput {
        authenticated_subject: &challenge.subject,
        bundle: &bundle(&challenge, true),
        transport_context_digest: &challenge.context_digest,
    });
    assert!(matches!(result, Err(Denial::ChallengeExpired)));
    assert_eq!(
        store.state(challenge.challenge_id.as_str(), 20),
        Ok(ChallengeState::ConsumedDeny(Denial::ChallengeExpired))
    );
}

#[test]
fn context_splice_and_composition_cycles_refuse() {
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    let (snapshot, challenge) = snapshot_and_challenge(100);
    let (verifier, store) = core(snapshot, clock.clone());
    store.issue(challenge.clone(), 1).expect("issue");
    let wrong_context = B64Url::from_bytes(&[9; 32]);
    let context_result = verifier.verify_at(
        VerificationInput {
            authenticated_subject: &challenge.subject,
            bundle: &bundle(&challenge, true),
            transport_context_digest: &wrong_context,
        },
        1,
    );
    assert!(matches!(context_result, Err(Denial::BindingMismatch)));

    let (snapshot, challenge) = snapshot_and_challenge(100);
    let (verifier, store) = core(snapshot, clock);
    store.issue(challenge.clone(), 1).expect("issue");
    let mut cyclic = bundle(&challenge, true);
    cyclic
        .binding_edges
        .as_mut()
        .expect("edge")
        .push(EvidenceBindingEdge {
            parent_component_id: "child".into(),
            child_component_id: "parent".into(),
            relation: "fixture-links-v1".into(),
            evidence: None,
        });
    let cycle_result = verifier.verify_at(
        VerificationInput {
            authenticated_subject: &challenge.subject,
            bundle: &cyclic,
            transport_context_digest: &challenge.context_digest,
        },
        1,
    );
    assert!(matches!(cycle_result, Err(Denial::Malformed)));
}
