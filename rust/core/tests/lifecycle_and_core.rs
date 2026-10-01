use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use binary_attestation_core::{
    B64Url, BindingRelationVerifier, Challenge, ChallengeState, ChallengeStore, Clock,
    CoreVerifier, Denial, EvidenceBindingEdge, EvidenceBundle, EvidenceComponent, EvidenceVerifier,
    InMemorySnapshotStore, PolicyDecision, PolicyEvaluator, ProviderRegistry, RelationRegistry,
    SecuritySnapshotStore, SignedSecuritySnapshot, VerificationInput, VerifiedComponent,
};
use serde_json::json;
use sha2::{Digest, Sha256};

static TEST_SUBJECT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn base_challenge() -> Challenge {
    let mut challenge: Challenge =
        serde_json::from_str(include_str!("../../../vectors/bcap1-transcript.json"))
            .ok()
            .and_then(|value: serde_json::Value| {
                serde_json::from_value(value["valid"][0]["input"].clone()).ok()
            })
            .expect("challenge fixture");
    // Parallel integration tests model separate relying-party test subjects.
    // This prevents unrelated fixtures from consuming one another's real
    // process-wide per-subject verification budget.
    challenge.subject = binary_attestation_core::AttestationSubject {
        kind: "did".into(),
        value: format!(
            "test-subject-{}",
            TEST_SUBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ),
    };
    challenge
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

#[test]
fn issue_reclaims_expired_issued_records_without_state_access() {
    let first = base_challenge();
    let mut second = first.clone();
    second.challenge_id = B64Url::from_bytes(&[7; 16]);
    second.expires_at_ms = serde_json::from_str("\"10\"").expect("u64");
    let store = ChallengeStore::new(1, 1);
    store.issue(first, 1).expect("first");

    // `issue` itself must transition the old ISSUED record before counting
    // quota; callers are not required to poll `state` to reclaim capacity.
    store.issue(second, 2).expect("expired record reclaimed");
}

#[test]
fn terminal_challenge_tombstones_are_skew_retained_then_pruned() {
    let first = base_challenge();
    let store = ChallengeStore::with_max_clock_skew(1, 2, 2);
    store.issue(first.clone(), 1).expect("issue");
    store
        .begin(
            first.challenge_id.as_str(),
            &first.subject,
            &first.subject,
            1,
        )
        .expect("claim");
    assert_eq!(
        store.finish(
            first.challenge_id.as_str(),
            Err(Denial::SignatureInvalid),
            1
        ),
        Err(Denial::SignatureInvalid)
    );

    // The terminal replay tombstone remains through expiresAt + skew.
    assert_eq!(
        store.state(first.challenge_id.as_str(), 3),
        Ok(ChallengeState::ConsumedDeny(Denial::SignatureInvalid))
    );
    assert_eq!(
        store.state(first.challenge_id.as_str(), 4),
        Err(Denial::ChallengeUnknown)
    );
}

#[test]
fn admission_tombstones_are_skew_retained_then_pruned() {
    let (snapshot, first) = snapshot_and_challenge(2);
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    let snapshots = InMemorySnapshotStore::with_clock_and_max_clock_skew(clock.clone(), 2);
    snapshots.publish(snapshot).expect("publish");
    assert!(matches!(
        snapshots.terminal_fence(&first, 100),
        Ok(binary_attestation_core::TerminalFence::Allowed { .. })
    ));

    // A reused ID remains fenced through expiry plus skew, even when a newer
    // challenge with that ID would otherwise be valid at the supplied time.
    let mut later = first.clone();
    later.expires_at_ms = serde_json::from_str("\"10\"").expect("u64");
    clock.set(3);
    assert_eq!(
        snapshots.terminal_fence(&later, 100),
        Ok(binary_attestation_core::TerminalFence::Denied {
            denial: Denial::ChallengeUsed,
            checked_at_ms: 3,
        })
    );
    clock.set(4);
    snapshots
        .terminal_fence(&later, 100)
        .expect("expired admission pruned after skew");
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

/// Returns a later trusted timestamp on each call, modelling a fence that
/// linearizes after verification has completed.
struct AdvancingClock(AtomicU64);
impl Clock for AdvancingClock {
    fn now_ms(&self) -> Result<u64, Denial> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

struct FixtureVerifier {
    clock: Option<Arc<ManualClock>>,
    advance_to: u64,
    valid_until: u64,
}

struct BlockingVerifier {
    entered: mpsc::Sender<()>,
    release: Arc<Barrier>,
    blocking_calls: AtomicUsize,
}
impl EvidenceVerifier for BlockingVerifier {
    fn provider(&self) -> &'static str {
        "fixture-v1"
    }
    fn verify(
        &self,
        component: &EvidenceComponent,
        expected: [u8; 64],
        _now: u64,
    ) -> Result<VerifiedComponent, Denial> {
        // Block only the first component of each of the first two requests.
        // That keeps both permits occupied while the third request is claimed.
        if self.blocking_calls.fetch_add(1, Ordering::SeqCst) < 2 {
            self.entered.send(()).map_err(|_| Denial::InternalError)?;
            self.release.wait();
        }
        Ok(VerifiedComponent {
            component_id: component.component_id.clone(),
            provider: component.provider.clone(),
            evidence_digest: B64Url::from_bytes(&Sha256::digest(
                component
                    .evidence
                    .decode_with_limit(binary_attestation_core::MAX_COMPONENT_EVIDENCE)
                    .expect("bounded evidence"),
            )),
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
            clock.set(self.advance_to);
        }
        Ok(VerifiedComponent {
            component_id: component.component_id.clone(),
            provider: component.provider.clone(),
            evidence_digest: B64Url::from_bytes(&Sha256::digest(
                component
                    .evidence
                    .decode_with_limit(binary_attestation_core::MAX_COMPONENT_EVIDENCE)
                    .expect("bounded evidence"),
            )),
            binding_digest: if component.component_id == "parent" {
                B64Url::from_bytes(&expected)
            } else {
                B64Url::from_bytes(&[0; 64])
            },
            platform: Default::default(),
            measurements: Default::default(),
            tcb: Default::default(),
            advisories: vec![],
            valid_until_ms: serde_json::from_value(json!(self.valid_until.to_string()))
                .expect("u64"),
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
struct AllowPolicy(u64);
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
            valid_until_ms: self.0,
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
    core_with_validity(snapshot, clock, 1, 100, 100)
}

fn core_with_validity(
    snapshot: SignedSecuritySnapshot,
    clock: Arc<ManualClock>,
    advance_to: u64,
    component_valid_until: u64,
    policy_valid_until: u64,
) -> (CoreVerifier, Arc<ChallengeStore>) {
    let snapshots = Arc::new(InMemorySnapshotStore::with_clock(clock.clone()));
    snapshots.publish(snapshot).expect("publish");
    let challenges = Arc::new(ChallengeStore::new(4, 10));
    let providers = Arc::new(ProviderRegistry::new());
    providers
        .register(Arc::new(FixtureVerifier {
            clock: Some(clock.clone()),
            advance_to,
            valid_until: component_valid_until,
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
            Arc::new(AllowPolicy(policy_valid_until)),
            clock,
        ),
        challenges,
    )
}

fn concurrency_core(
    snapshot: SignedSecuritySnapshot,
    clock: Arc<ManualClock>,
    provider: Arc<dyn EvidenceVerifier>,
) -> (CoreVerifier, Arc<ChallengeStore>) {
    let snapshots = Arc::new(InMemorySnapshotStore::with_clock(clock.clone()));
    snapshots.publish(snapshot).expect("publish");
    let challenges = Arc::new(ChallengeStore::new(8, 10));
    let providers = Arc::new(ProviderRegistry::new());
    providers.register(provider).expect("provider");
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
            Arc::new(AllowPolicy(100)),
            clock,
        ),
        challenges,
    )
}

#[test]
fn verification_concurrency_is_bounded_and_permits_are_released() {
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    let (snapshot, mut base) = snapshot_and_challenge(100);
    // Test the subject-scoped limit without contending with the fixture
    // subject used by independent tests running in parallel.
    base.subject.value = "concurrency-subject".into();
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new(Barrier::new(3));
    let provider: Arc<dyn EvidenceVerifier> = Arc::new(BlockingVerifier {
        entered: entered_tx,
        release: release.clone(),
        blocking_calls: AtomicUsize::new(0),
    });
    let (core, store) = concurrency_core(snapshot, clock, provider);
    let core = Arc::new(core);

    let mut challenges = Vec::new();
    for byte in 1..=4 {
        let mut challenge = base.clone();
        challenge.challenge_id = B64Url::from_bytes(&[byte; 16]);
        store.issue(challenge.clone(), 1).expect("issue");
        challenges.push(challenge);
    }
    let mut handles = Vec::new();
    for challenge in challenges.iter().take(2).cloned() {
        let core = core.clone();
        handles.push(thread::spawn(move || {
            core.verify(VerificationInput {
                authenticated_subject: &challenge.subject,
                bundle: &bundle(&challenge, true),
                transport_context_digest: &challenge.context_digest,
            })
        }));
    }
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first verification entered provider");
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second verification entered provider");

    let third = &challenges[2];
    assert!(matches!(
        core.verify(VerificationInput {
            authenticated_subject: &third.subject,
            bundle: &bundle(third, true),
            transport_context_digest: &third.context_digest,
        }),
        Err(Denial::ResourceLimit)
    ));
    assert_eq!(
        store.state(third.challenge_id.as_str(), 1),
        Ok(ChallengeState::ConsumedDeny(Denial::ResourceLimit))
    );

    release.wait();
    for handle in handles {
        assert!(handle.join().expect("thread").is_ok());
    }
    let fourth = &challenges[3];
    assert!(
        core.verify(VerificationInput {
            authenticated_subject: &fourth.subject,
            bundle: &bundle(fourth, true),
            transport_context_digest: &fourth.context_digest,
        })
        .is_ok()
    );
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
    let (core, store) = core(snapshot, clock.clone());
    store.issue(challenge.clone(), 1).expect("issue");
    clock.set(1);
    let denied = core.verify(VerificationInput {
        authenticated_subject: &challenge.subject,
        bundle: &bundle(&challenge, false),
        transport_context_digest: &challenge.context_digest,
    });
    assert!(matches!(denied, Err(Denial::ComponentUnbound)));
}

#[test]
fn verification_rechecks_trusted_clock_before_allow() {
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    let (snapshot, challenge) = snapshot_and_challenge(2);
    let (verifier, store) = core_with_validity(snapshot, clock.clone(), 20, 100, 100);
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
fn terminal_fence_samples_time_after_verification_and_denies_at_expiry() {
    // The verifier's initial challenge check sees t=1. No provider advances
    // time; the snapshot-store fence itself samples t=2 under its write lock,
    // where expiry is exclusive and must deny.
    let clock: Arc<dyn Clock> = Arc::new(AdvancingClock(AtomicU64::new(1)));
    let (snapshot, challenge) = snapshot_and_challenge(2);
    let snapshots = Arc::new(InMemorySnapshotStore::with_clock(clock.clone()));
    snapshots.publish(snapshot).expect("publish");
    let challenges = Arc::new(ChallengeStore::new(4, 10));
    challenges.issue(challenge.clone(), 1).expect("issue");
    let providers = Arc::new(ProviderRegistry::new());
    providers
        .register(Arc::new(FixtureVerifier {
            clock: None,
            advance_to: 0,
            valid_until: 100,
        }))
        .expect("provider");
    let relations = Arc::new(RelationRegistry::new());
    relations
        .register(Arc::new(FixtureRelation))
        .expect("relation");
    let verifier = CoreVerifier::with_clock(
        challenges.clone(),
        snapshots,
        providers,
        relations,
        Arc::new(AllowPolicy(100)),
        clock,
    );

    assert!(matches!(
        verifier.verify(VerificationInput {
            authenticated_subject: &challenge.subject,
            bundle: &bundle(&challenge, true),
            transport_context_digest: &challenge.context_digest,
        }),
        Err(Denial::ChallengeExpired)
    ));
    assert_eq!(
        challenges.state(challenge.challenge_id.as_str(), 2),
        Ok(ChallengeState::ConsumedDeny(Denial::ChallengeExpired))
    );
}

#[test]
fn verification_refuses_claims_expired_at_terminal_fence() {
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    // Provider validity expires while verification runs, but the challenge is
    // still live. A stale claim must not reach the shared allow fence.
    let (snapshot, challenge) = snapshot_and_challenge(20);
    let (verifier, store) = core_with_validity(snapshot, clock, 2, 2, 100);
    store.issue(challenge.clone(), 1).expect("issue");
    let result = verifier.verify(VerificationInput {
        authenticated_subject: &challenge.subject,
        bundle: &bundle(&challenge, true),
        transport_context_digest: &challenge.context_digest,
    });
    assert!(matches!(result, Err(Denial::EndorsementsStale)));
    assert_eq!(
        store.state(challenge.challenge_id.as_str(), 2),
        Ok(ChallengeState::ConsumedDeny(Denial::EndorsementsStale))
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
    let context_result = verifier.verify(VerificationInput {
        authenticated_subject: &challenge.subject,
        bundle: &bundle(&challenge, true),
        transport_context_digest: &wrong_context,
    });
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
    let cycle_result = verifier.verify(VerificationInput {
        authenticated_subject: &challenge.subject,
        bundle: &cyclic,
        transport_context_digest: &challenge.context_digest,
    });
    assert!(matches!(cycle_result, Err(Denial::Malformed)));
}

struct CountingVerifier {
    inner: FixtureVerifier,
    calls: Arc<AtomicUsize>,
}
impl EvidenceVerifier for CountingVerifier {
    fn provider(&self) -> &'static str {
        self.inner.provider()
    }
    fn verify(
        &self,
        component: &EvidenceComponent,
        expected: [u8; 64],
        now: u64,
    ) -> Result<VerifiedComponent, Denial> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(component, expected, now)
    }
}

#[test]
fn graph_and_plugin_preflight_precede_every_provider_call() {
    type Mutate = fn(&mut EvidenceBundle);
    let cases: [(&str, Mutate, Denial); 4] = [
        (
            "self edge",
            |bundle| {
                bundle.binding_edges = Some(vec![EvidenceBindingEdge {
                    parent_component_id: "parent".into(),
                    child_component_id: "parent".into(),
                    relation: "fixture-links-v1".into(),
                    evidence: None,
                }]);
            },
            Denial::Malformed,
        ),
        (
            "cycle",
            |bundle| {
                bundle
                    .binding_edges
                    .as_mut()
                    .expect("edge")
                    .push(EvidenceBindingEdge {
                        parent_component_id: "child".into(),
                        child_component_id: "parent".into(),
                        relation: "fixture-links-v1".into(),
                        evidence: None,
                    });
            },
            Denial::Malformed,
        ),
        (
            "unregistered relation",
            |bundle| {
                bundle.binding_edges.as_mut().expect("edge")[0].relation = "absent-links-v1".into();
            },
            Denial::UnsupportedProvider,
        ),
        (
            "unregistered provider on a later component",
            |bundle| bundle.components[1].provider = "absent-v1".into(),
            Denial::UnsupportedProvider,
        ),
    ];
    for (name, mutate, expected) in cases {
        let clock = Arc::new(ManualClock::default());
        clock.set(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let (snapshot, challenge) = snapshot_and_challenge(100);
        let (verifier, store) = concurrency_core(
            snapshot,
            clock,
            Arc::new(CountingVerifier {
                inner: FixtureVerifier {
                    clock: None,
                    advance_to: 1,
                    valid_until: 100,
                },
                calls: calls.clone(),
            }),
        );
        store.issue(challenge.clone(), 1).expect("issue");
        let mut candidate = bundle(&challenge, true);
        mutate(&mut candidate);
        let result = verifier.verify(VerificationInput {
            authenticated_subject: &challenge.subject,
            bundle: &candidate,
            transport_context_digest: &challenge.context_digest,
        });
        assert_eq!(result.map(|_| ()), Err(expected), "{name}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{name}: provider ran");
    }
    // Control: the same harness reaches the provider for a valid bundle.
    let clock = Arc::new(ManualClock::default());
    clock.set(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let (snapshot, challenge) = snapshot_and_challenge(100);
    let (verifier, store) = concurrency_core(
        snapshot,
        clock,
        Arc::new(CountingVerifier {
            inner: FixtureVerifier {
                clock: None,
                advance_to: 1,
                valid_until: 100,
            },
            calls: calls.clone(),
        }),
    );
    store.issue(challenge.clone(), 1).expect("issue");
    verifier
        .verify(VerificationInput {
            authenticated_subject: &challenge.subject,
            bundle: &bundle(&challenge, true),
            transport_context_digest: &challenge.context_digest,
        })
        .expect("valid bundle");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
