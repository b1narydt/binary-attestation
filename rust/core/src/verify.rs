use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use sha2::{Digest, Sha256};

use crate::{
    AttestationSubject, B64Url, Challenge, ChallengeStore, Clock, Denial, EvidenceBundle,
    PolicyEvaluator, ProviderRegistry, RelationRegistry, SecuritySnapshotStore,
    SignedSecuritySnapshot, VerifiedClaims, VerifiedComponent, constant_time_eq,
};

/// Input supplied by an authenticated channel adapter.  `transport_context_digest`
/// is mandatory for envelope-based evidence and is checked against the stored
/// challenge after selecting its challenge id.
pub struct VerificationInput<'a> {
    pub authenticated_subject: &'a AttestationSubject,
    pub bundle: &'a EvidenceBundle,
    /// The envelope context supplied by an authenticated BCAP1 transport.
    /// Direct adapters pass the locally stored challenge's context explicitly.
    pub transport_context_digest: &'a B64Url,
}

pub struct CoreVerifier {
    challenges: Arc<ChallengeStore>,
    snapshots: Arc<dyn SecuritySnapshotStore>,
    providers: Arc<ProviderRegistry>,
    relations: Arc<RelationRegistry>,
    policy: Arc<dyn PolicyEvaluator>,
    clock: Arc<dyn Clock>,
}

impl CoreVerifier {
    pub fn new(
        challenges: Arc<ChallengeStore>,
        snapshots: Arc<dyn SecuritySnapshotStore>,
        providers: Arc<ProviderRegistry>,
        relations: Arc<RelationRegistry>,
        policy: Arc<dyn PolicyEvaluator>,
    ) -> Self {
        Self::with_clock(
            challenges,
            snapshots,
            providers,
            relations,
            policy,
            Arc::new(crate::SystemClock),
        )
    }

    pub fn with_clock(
        challenges: Arc<ChallengeStore>,
        snapshots: Arc<dyn SecuritySnapshotStore>,
        providers: Arc<ProviderRegistry>,
        relations: Arc<RelationRegistry>,
        policy: Arc<dyn PolicyEvaluator>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            challenges,
            snapshots,
            providers,
            relations,
            policy,
            clock,
        }
    }

    /// Runs the provider-neutral verification pipeline.  A successful result
    /// consumes the challenge; every failure after atomic claim consumes it as
    /// a terminal denial.
    pub fn verify(&self, input: VerificationInput<'_>) -> Result<VerifiedClaims, Denial> {
        let now_ms = self.clock.now_ms()?;
        self.verify_started(input, now_ms)
    }

    fn verify_started(
        &self,
        input: VerificationInput<'_>,
        now_ms: u64,
    ) -> Result<VerifiedClaims, Denial> {
        input.bundle.validate()?;
        input.authenticated_subject.validate()?;
        let challenge = self.challenges.begin(
            input.bundle.challenge_id.as_str(),
            input.authenticated_subject,
            &input.bundle.subject,
            now_ms,
        )?;
        let _permit = match self
            .challenges
            .acquire_verification_permit(&challenge.subject)
        {
            Ok(permit) => permit,
            Err(denial) => {
                return match self.challenges.finish(
                    challenge.challenge_id.as_str(),
                    Err(denial),
                    now_ms,
                ) {
                    Err(terminal_denial) => Err(terminal_denial),
                    Ok(()) => Err(denial),
                };
            }
        };
        let result = self.verify_claimed(&challenge, input, now_ms);
        let terminal_now = match self.clock.now_ms() {
            Ok(now) => now,
            Err(denial) => {
                let _ = self
                    .challenges
                    .finish_clock_failure(challenge.challenge_id.as_str());
                return Err(denial);
            }
        };
        match result {
            Ok(claims) => {
                // All validity windows are exclusive. Do not commit a shared
                // allow whose returned claims are already unusable at the
                // terminal fence, even if the challenge itself remains live.
                if claims.valid_until_ms.get() <= terminal_now {
                    return match self.challenges.finish(
                        challenge.challenge_id.as_str(),
                        Err(Denial::EndorsementsStale),
                        terminal_now,
                    ) {
                        Err(terminal_denial) => Err(terminal_denial),
                        Ok(()) => Err(Denial::EndorsementsStale),
                    };
                }
                // Commit at the shared epoch fence first. The local store is a
                // cache/mirror only; it cannot remain allowed if that shared
                // transaction refuses.
                match self.snapshots.terminal_fence(&challenge, terminal_now) {
                    Ok(()) => {
                        self.challenges.finish(
                            challenge.challenge_id.as_str(),
                            Ok(()),
                            terminal_now,
                        )?;
                        Ok(claims)
                    }
                    Err(denial) => match self.challenges.finish(
                        challenge.challenge_id.as_str(),
                        Err(denial),
                        terminal_now,
                    ) {
                        Err(terminal_denial) => Err(terminal_denial),
                        Ok(()) => Err(denial),
                    },
                }
            }
            Err(denial) => {
                match self.challenges.finish(
                    challenge.challenge_id.as_str(),
                    Err(denial),
                    terminal_now,
                ) {
                    Err(terminal_denial) => Err(terminal_denial),
                    Ok(()) => Err(denial),
                }
            }
        }
    }

    fn verify_claimed(
        &self,
        challenge: &Challenge,
        input: VerificationInput<'_>,
        now_ms: u64,
    ) -> Result<VerifiedClaims, Denial> {
        if input.transport_context_digest != &challenge.context_digest {
            return Err(Denial::BindingMismatch);
        }
        let snapshot = self.current_matching_snapshot(challenge, now_ms)?;
        let expected_binding = challenge.binding_digest()?;
        let mut verified = Vec::with_capacity(input.bundle.components.len());
        for component in &input.bundle.components {
            let verifier = self.providers.get(&component.provider)?;
            let output = verifier.verify(component, expected_binding, now_ms)?;
            output.validate()?;
            if output.component_id != component.component_id
                || output.provider != component.provider
            {
                return Err(Denial::Malformed);
            }
            if !constant_time_eq(
                &Sha256::digest(
                    component
                        .evidence
                        .decode_with_limit(crate::MAX_COMPONENT_EVIDENCE)?,
                ),
                &output.evidence_digest.bytes::<32>()?,
            ) {
                return Err(Denial::BindingMismatch);
            }
            verified.push(output);
        }
        validate_composition(
            input.bundle,
            &verified,
            &self.relations,
            expected_binding,
            now_ms,
        )?;
        let decision = self
            .policy
            .evaluate(challenge, &verified, &snapshot, now_ms)?;
        // A security update while evidence/policy work was underway wins over
        // an otherwise valid result.
        let current = self.current_matching_snapshot(challenge, now_ms)?;
        let valid_until_ms = decision
            .valid_until_ms
            .min(challenge.expires_at_ms.get())
            .min(snapshot.body.valid_until_ms.get())
            .min(current.body.valid_until_ms.get())
            .min(
                verified
                    .iter()
                    .map(|component| component.valid_until_ms.get())
                    .min()
                    .ok_or(Denial::ComponentMissing)?,
            );
        decision.claims(challenge, verified, now_ms, valid_until_ms)
    }

    fn current_matching_snapshot(
        &self,
        challenge: &Challenge,
        now_ms: u64,
    ) -> Result<Arc<SignedSecuritySnapshot>, Denial> {
        let snapshot = self.snapshots.current()?;
        snapshot
            .validate()
            .map_err(|_| Denial::TrustSnapshotInvalid)?;
        if !snapshot.is_valid_at(now_ms) {
            return Err(Denial::TrustSnapshotInvalid);
        }
        if snapshot.body.security_epoch != challenge.security_epoch
            || snapshot.body.policy_id != challenge.policy_id
            || snapshot.body.policy_digest != challenge.policy_digest
            || snapshot.trust_digest != challenge.trust_digest
        {
            return Err(Denial::SecurityEpochChanged);
        }
        Ok(snapshot)
    }
}

fn validate_composition(
    bundle: &EvidenceBundle,
    components: &[VerifiedComponent],
    relations: &RelationRegistry,
    expected_binding: [u8; 64],
    now_ms: u64,
) -> Result<(), Denial> {
    if components.len() != bundle.components.len() {
        return Err(Denial::ComponentMissing);
    }
    let by_id = components
        .iter()
        .map(|component| (component.component_id.as_str(), component))
        .collect::<HashMap<_, _>>();
    let edges = bundle.binding_edges.as_deref().unwrap_or_default();
    let mut outgoing: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut edge_set = HashSet::new();
    for edge in edges {
        if !edge_set.insert((&edge.parent_component_id, &edge.child_component_id)) {
            return Err(Denial::Malformed);
        }
        let parent = by_id
            .get(edge.parent_component_id.as_str())
            .ok_or(Denial::Malformed)?;
        let child = by_id
            .get(edge.child_component_id.as_str())
            .ok_or(Denial::Malformed)?;
        let verifier = relations.get(&edge.relation)?;
        verifier.verify(parent, child, edge, expected_binding, now_ms)?;
        outgoing
            .entry(edge.child_component_id.as_str())
            .or_default()
            .push(edge.parent_component_id.as_str());
    }
    let mut directed = HashMap::<&str, Vec<&str>>::new();
    for edge in edges {
        directed
            .entry(edge.parent_component_id.as_str())
            .or_default()
            .push(edge.child_component_id.as_str());
    }
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    if components.iter().any(|component| {
        has_cycle(
            component.component_id.as_str(),
            &directed,
            &mut visiting,
            &mut visited,
        )
    }) {
        return Err(Denial::Malformed);
    }
    // Edges point parent -> child, so following child-to-parent requires every
    // component to reach a direct authenticated BCAP1 binding.  This accepts
    // an indirect child only after its registered relation is verified.
    for component in components {
        let mut visiting = HashSet::new();
        if !reaches_direct_binding(
            component.component_id.as_str(),
            &by_id,
            &outgoing,
            &expected_binding,
            &mut visiting,
        ) {
            return Err(Denial::ComponentUnbound);
        }
    }
    Ok(())
}

fn has_cycle<'a>(
    node: &'a str,
    edges: &HashMap<&'a str, Vec<&'a str>>,
    visiting: &mut HashSet<&'a str>,
    visited: &mut HashSet<&'a str>,
) -> bool {
    if visited.contains(node) {
        return false;
    }
    if !visiting.insert(node) {
        return true;
    }
    let found = edges.get(node).is_some_and(|children| {
        children
            .iter()
            .any(|child| has_cycle(child, edges, visiting, visited))
    });
    visiting.remove(node);
    visited.insert(node);
    found
}

fn reaches_direct_binding(
    component_id: &str,
    components: &HashMap<&str, &VerifiedComponent>,
    parents: &HashMap<&str, Vec<&str>>,
    expected_binding: &[u8; 64],
    visiting: &mut HashSet<String>,
) -> bool {
    if !visiting.insert(component_id.to_owned()) {
        return false;
    }
    let direct = components.get(component_id).is_some_and(|component| {
        component
            .binding_digest
            .bytes::<64>()
            .is_ok_and(|digest| constant_time_eq(&digest, expected_binding))
    });
    let result = direct
        || parents.get(component_id).is_some_and(|parent_ids| {
            parent_ids.iter().any(|parent| {
                reaches_direct_binding(parent, components, parents, expected_binding, visiting)
            })
        });
    visiting.remove(component_id);
    result
}
