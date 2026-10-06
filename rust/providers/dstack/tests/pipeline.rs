//! Bundle-level behaviour on the live captures.
//!
//! The live probe challenges carry `trustDigest = SHA-256("live-probe-trust")`
//! rather than a commitment to a signed security-snapshot body, so the real
//! `CoreVerifier` refuses them before any plugin runs (proven below). The
//! positive bundle path therefore runs the registered plugins in the core's
//! own order (`verify.rs::verify_claimed` after the snapshot step): provider
//! verification with evidence-digest and id checks, relation edges, the
//! direct-binding reachability rule, then the policy.

mod common;

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use binary_attestation_core::{
    B64Url, BindingRelationVerifier, Challenge, ChallengeStore, CoreVerifier, Denial,
    EvidenceBindingEdge, EvidenceBundle, EvidenceComponent, EvidenceVerifier,
    InMemorySnapshotStore, MAX_COMPONENT_EVIDENCE, PolicyEvaluator, ProviderRegistry,
    RelationRegistry, SignedSecuritySnapshot, VerificationInput, VerifiedClaims, VerifiedComponent,
    constant_time_eq,
};
use binary_attestation_dstack::{DSTACK_SUBJECT_KEY_BRC100_RELATION, DstackBrc100IdentityPolicy};
use common::*;
use sha2::{Digest, Sha256};

struct Counting<T>(T, AtomicUsize);

impl<T: EvidenceVerifier> EvidenceVerifier for Counting<T> {
    fn provider(&self) -> &'static str {
        self.0.provider()
    }
    fn verify(
        &self,
        component: &EvidenceComponent,
        expected_binding: [u8; 64],
        now_ms: u64,
    ) -> Result<VerifiedComponent, Denial> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.verify(component, expected_binding, now_ms)
    }
}

impl<T: BindingRelationVerifier> BindingRelationVerifier for Counting<T> {
    fn relation(&self) -> &'static str {
        self.0.relation()
    }
    fn verify(
        &self,
        parent: &VerifiedComponent,
        child: &VerifiedComponent,
        edge: &EvidenceBindingEdge,
        expected_binding: [u8; 64],
        now_ms: u64,
    ) -> Result<(), Denial> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.verify(parent, child, edge, expected_binding, now_ms)
    }
}

impl<T: PolicyEvaluator> PolicyEvaluator for Counting<T> {
    fn evaluate(
        &self,
        challenge: &Challenge,
        claims: &[VerifiedComponent],
        snapshot: &SignedSecuritySnapshot,
        now_ms: u64,
    ) -> Result<binary_attestation_core::PolicyDecision, Denial> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.evaluate(challenge, claims, snapshot, now_ms)
    }
}

struct Plugins {
    providers: Arc<ProviderRegistry>,
    relations: Arc<RelationRegistry>,
    policy: Arc<Counting<DstackBrc100IdentityPolicy>>,
    provider_calls: Arc<Counting<binary_attestation_dstack::DstackAttestV0Verifier>>,
    child_calls: Arc<Counting<binary_attestation_dstack::DstackSubjectKeyV0Verifier>>,
    relation_calls: Arc<Counting<binary_attestation_dstack::DstackSubjectKeyBrc100Relation>>,
}

fn plugins() -> Plugins {
    let providers = Arc::new(ProviderRegistry::new());
    let provider_calls = Arc::new(Counting(attest_verifier(), AtomicUsize::new(0)));
    let child_calls = Arc::new(Counting(subject_key_verifier(), AtomicUsize::new(0)));
    providers.register(provider_calls.clone()).expect("parent");
    providers.register(child_calls.clone()).expect("child");
    let relations = Arc::new(RelationRegistry::new());
    let relation_calls = Arc::new(Counting(relation(), AtomicUsize::new(0)));
    relations
        .register(relation_calls.clone())
        .expect("relation");
    Plugins {
        providers,
        relations,
        policy: Arc::new(Counting(policy(), AtomicUsize::new(0))),
        provider_calls,
        child_calls,
        relation_calls,
    }
}

fn bundle(
    probe: &Probe,
    components: Vec<EvidenceComponent>,
    edges: Vec<EvidenceBindingEdge>,
) -> EvidenceBundle {
    EvidenceBundle {
        protocol_version: 1,
        challenge_id: probe.challenge.challenge_id.clone(),
        subject: probe.challenge.subject.clone(),
        components,
        binding_edges: Some(edges),
    }
}

fn full_bundle(probe: &Probe) -> EvidenceBundle {
    bundle(
        probe,
        vec![parent_component(probe), child_component(probe)],
        vec![edge()],
    )
}

/// Mirrors `CoreVerifier::verify_claimed` after the snapshot/epoch step.
fn run_pipeline(
    plugins: &Plugins,
    probe: &Probe,
    bundle: &EvidenceBundle,
) -> Result<VerifiedClaims, Denial> {
    bundle.validate()?;
    let expected = probe.binding;
    let now_ms = probe.now_ms();
    let snapshot = snapshot(&probe.challenge);
    let providers = bundle
        .components
        .iter()
        .map(|component| plugins.providers.get(&component.provider))
        .collect::<Result<Vec<_>, _>>()?;
    let edges = bundle.binding_edges.as_deref().unwrap_or_default();
    let relations = edges
        .iter()
        .map(|edge| plugins.relations.get(&edge.relation))
        .collect::<Result<Vec<_>, _>>()?;
    let mut verified = Vec::new();
    for (component, verifier) in bundle.components.iter().zip(providers) {
        let output = verifier.verify(component, expected, now_ms)?;
        output.validate()?;
        if output.component_id != component.component_id || output.provider != component.provider {
            return Err(Denial::Malformed);
        }
        let digest = Sha256::digest(
            component
                .evidence
                .decode_with_limit(MAX_COMPONENT_EVIDENCE)?,
        );
        if !constant_time_eq(&digest, &output.evidence_digest.bytes::<32>()?) {
            return Err(Denial::BindingMismatch);
        }
        verified.push(output);
    }
    let by_id = verified
        .iter()
        .map(|component| (component.component_id.as_str(), component))
        .collect::<HashMap<_, _>>();
    let mut parents: HashMap<&str, Vec<&str>> = HashMap::new();
    for (edge, verifier) in edges.iter().zip(relations) {
        let parent = by_id[edge.parent_component_id.as_str()];
        let child = by_id[edge.child_component_id.as_str()];
        verifier.verify(parent, child, edge, expected, now_ms)?;
        parents
            .entry(edge.child_component_id.as_str())
            .or_default()
            .push(edge.parent_component_id.as_str());
    }
    fn reaches(
        id: &str,
        by_id: &HashMap<&str, &VerifiedComponent>,
        parents: &HashMap<&str, Vec<&str>>,
        expected: &[u8; 64],
        visiting: &mut HashSet<String>,
    ) -> bool {
        if !visiting.insert(id.to_owned()) {
            return false;
        }
        let direct = by_id[id]
            .binding_digest
            .bytes::<64>()
            .is_ok_and(|digest| constant_time_eq(&digest, expected));
        let result = direct
            || parents.get(id).is_some_and(|ids| {
                ids.iter()
                    .any(|parent| reaches(parent, by_id, parents, expected, visiting))
            });
        visiting.remove(id);
        result
    }
    for component in &verified {
        if !reaches(
            &component.component_id,
            &by_id,
            &parents,
            &expected,
            &mut HashSet::new(),
        ) {
            return Err(Denial::ComponentUnbound);
        }
    }
    let decision = plugins
        .policy
        .evaluate(&probe.challenge, &verified, &snapshot, now_ms)?;
    let valid_until = decision
        .valid_until_ms
        .min(probe.challenge.expires_at_ms.get())
        .min(
            verified
                .iter()
                .map(|component| component.valid_until_ms.get())
                .min()
                .ok_or(Denial::ComponentMissing)?,
        );
    decision.claims(&probe.challenge, verified, now_ms, valid_until)
}

#[test]
fn brc100_live_bundle_is_allowed_through_the_core_order_pipeline() {
    let probe = probe_brc100();
    let plugins = plugins();
    let claims = run_pipeline(&plugins, &probe, &full_bundle(&probe)).expect("allowed");
    assert_eq!(claims.subject, probe.challenge.subject);
    assert_eq!(claims.subject.value, probe.identity.public_key);
    assert_eq!(claims.subject_binding, DSTACK_SUBJECT_KEY_BRC100_RELATION);
    assert_eq!(claims.binding_digest, B64Url::from_bytes(&probe.binding));
    assert_eq!(claims.components.len(), 2);
    assert_eq!(
        claims.valid_until_ms.get(),
        probe.challenge.expires_at_ms.get(),
        "capped to the challenge, which expires before the collateral"
    );
    assert_eq!(plugins.provider_calls.1.load(Ordering::SeqCst), 1);
    assert_eq!(plugins.child_calls.1.load(Ordering::SeqCst), 1);
    assert_eq!(plugins.relation_calls.1.load(Ordering::SeqCst), 1);
    assert_eq!(plugins.policy.1.load(Ordering::SeqCst), 1);
}

#[test]
fn did_live_bundle_fails_only_at_the_policy_subject_check() {
    let probe = probe_did();
    let plugins = plugins();
    assert_eq!(
        run_pipeline(&plugins, &probe, &full_bundle(&probe)).err(),
        Some(Denial::SubjectMismatch)
    );
    assert_eq!(plugins.provider_calls.1.load(Ordering::SeqCst), 1);
    assert_eq!(plugins.child_calls.1.load(Ordering::SeqCst), 1);
    assert_eq!(plugins.relation_calls.1.load(Ordering::SeqCst), 1);
    assert_eq!(plugins.policy.1.load(Ordering::SeqCst), 1);
}

#[test]
fn standalone_child_without_an_edge_is_component_unbound_before_policy() {
    let probe = probe_brc100();
    let plugins = plugins();
    let bundle = bundle(
        &probe,
        vec![parent_component(&probe), child_component(&probe)],
        vec![],
    );
    assert_eq!(
        run_pipeline(&plugins, &probe, &bundle).err(),
        Some(Denial::ComponentUnbound)
    );
    assert_eq!(plugins.policy.1.load(Ordering::SeqCst), 0);
    let only_child = common::bundle_components_only(&probe, vec![child_component(&probe)]);
    assert_eq!(
        run_pipeline(&plugins, &probe, &only_child).err(),
        Some(Denial::ComponentUnbound)
    );
    assert_eq!(plugins.policy.1.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_parent_stops_the_bundle_before_the_relation_and_policy() {
    let probe = probe_brc100();
    let plugins = plugins();
    let mut tampered = probe.envelope.clone();
    let last = tampered.len() - 1;
    flip_bit(&mut tampered, last); // config tail -> malformed JSON
    let bundle = bundle(
        &probe,
        vec![parent_component_from(&tampered), child_component(&probe)],
        vec![edge()],
    );
    assert_eq!(
        run_pipeline(&plugins, &probe, &bundle).err(),
        Some(Denial::Malformed)
    );
    assert_eq!(plugins.provider_calls.1.load(Ordering::SeqCst), 1);
    assert_eq!(plugins.child_calls.1.load(Ordering::SeqCst), 0);
    assert_eq!(plugins.relation_calls.1.load(Ordering::SeqCst), 0);
    assert_eq!(plugins.policy.1.load(Ordering::SeqCst), 0);
}

#[test]
fn child_from_the_other_capture_fails_before_the_relation() {
    let brc100 = probe_brc100();
    let did = probe_did();
    let plugins = plugins();
    let bundle = bundle(
        &brc100,
        vec![parent_component(&brc100), child_component(&did)],
        vec![edge()],
    );
    assert_eq!(
        run_pipeline(&plugins, &brc100, &bundle).err(),
        Some(Denial::SignatureInvalid)
    );
    assert_eq!(plugins.relation_calls.1.load(Ordering::SeqCst), 0);
    assert_eq!(plugins.policy.1.load(Ordering::SeqCst), 0);
}

#[test]
fn unregistered_mock_provider_is_refused_before_any_plugin_runs() {
    let probe = probe_brc100();
    let plugins = plugins();
    let mut mock = parent_component(&probe);
    mock.provider = "mock-dstack-attest-v0".into();
    let bundle = bundle(&probe, vec![mock, child_component(&probe)], vec![edge()]);
    assert_eq!(
        run_pipeline(&plugins, &probe, &bundle).err(),
        Some(Denial::UnsupportedProvider)
    );
    assert_eq!(plugins.provider_calls.1.load(Ordering::SeqCst), 0);
    assert_eq!(plugins.child_calls.1.load(Ordering::SeqCst), 0);
}

#[test]
fn core_verifier_refuses_the_live_challenge_without_a_snapshot_commitment() {
    // The probe challenge's trustDigest is SHA-256("live-probe-trust"), not a
    // JCS snapshot-body digest, so no publishable snapshot can match it. The
    // core must deny at the epoch check and never reach a plugin.
    let probe = probe_brc100();
    let plugins = plugins();
    let clock = Arc::new(FrozenClock(probe.now_ms()));
    let snapshots = Arc::new(InMemorySnapshotStore::with_clock(clock.clone()));
    snapshots
        .publish(snapshot(&probe.challenge))
        .expect("publish");
    let challenges = Arc::new(ChallengeStore::new(4, 10));
    challenges
        .issue(probe.challenge.clone(), probe.now_ms())
        .expect("issue");
    let core = CoreVerifier::with_clock(
        challenges,
        snapshots,
        plugins.providers.clone(),
        plugins.relations.clone(),
        plugins.policy.clone(),
        clock,
    );
    let bundle = full_bundle(&probe);
    let result = core.verify(VerificationInput {
        authenticated_subject: &probe.challenge.subject,
        bundle: &bundle,
        transport_context_digest: &probe.challenge.context_digest,
    });
    assert_eq!(result.err(), Some(Denial::SecurityEpochChanged));
    assert_eq!(plugins.provider_calls.1.load(Ordering::SeqCst), 0);
    assert_eq!(plugins.child_calls.1.load(Ordering::SeqCst), 0);
    assert_eq!(plugins.relation_calls.1.load(Ordering::SeqCst), 0);
    assert_eq!(plugins.policy.1.load(Ordering::SeqCst), 0);
}
