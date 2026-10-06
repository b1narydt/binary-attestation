use std::{
    collections::{HashMap, hash_map::Entry},
    sync::{Arc, RwLock},
};

use crate::{
    Challenge, Denial, EvidenceBindingEdge, EvidenceComponent, SignedSecuritySnapshot,
    VerifiedClaims, VerifiedComponent,
};

/// Provider-specific evidence verification, implemented outside this crate.
pub trait EvidenceVerifier: Send + Sync {
    fn provider(&self) -> &'static str;
    fn verify(
        &self,
        component: &EvidenceComponent,
        expected_binding: [u8; 64],
        now_ms: u64,
    ) -> Result<VerifiedComponent, Denial>;
}

/// Verifies a registered cryptographic relation between two verified
/// components.  Mere co-delivery is never a relation.
pub trait BindingRelationVerifier: Send + Sync {
    fn relation(&self) -> &'static str;
    fn verify(
        &self,
        parent: &VerifiedComponent,
        child: &VerifiedComponent,
        edge: &EvidenceBindingEdge,
        expected_binding: [u8; 64],
        now_ms: u64,
    ) -> Result<(), Denial>;
}

/// The policy receives normalized provider claims, never untrusted metadata.
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(
        &self,
        challenge: &Challenge,
        claims: &[VerifiedComponent],
        snapshot: &SignedSecuritySnapshot,
        now_ms: u64,
    ) -> Result<PolicyDecision, Denial>;
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// Names the independently verified mechanism that bound the workload to
    /// the subject.  An empty string is rejected.
    pub subject_binding: String,
    /// Policy-selected cap over provider validity.  The core also caps it to
    /// challenge and snapshot expiry.
    pub valid_until_ms: u64,
}

impl PolicyDecision {
    pub fn claims(
        self,
        challenge: &Challenge,
        components: Vec<VerifiedComponent>,
        verified_at_ms: u64,
        valid_until_ms: u64,
    ) -> Result<VerifiedClaims, Denial> {
        crate::validate_text(&self.subject_binding)?;
        if self.subject_binding.is_empty() || valid_until_ms <= verified_at_ms {
            return Err(Denial::PolicyMismatch);
        }
        Ok(VerifiedClaims::from_challenge(
            challenge,
            components,
            self.subject_binding,
            verified_at_ms,
            valid_until_ms,
        ))
    }
}

/// `test` as a complete segment of a delimited provider name (`test-v1`,
/// `fixture-test-v1`, `test`), never as a substring of another word.
fn is_reserved_test_name(name: &str) -> bool {
    name.split(['-', '_', '.', ':', '/'])
        .any(|segment| segment.eq_ignore_ascii_case("test"))
}

#[derive(Default)]
pub struct ProviderRegistry {
    verifiers: RwLock<HashMap<String, Arc<dyn EvidenceVerifier>>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a production verifier.  The core has no mock provider; names
    /// reserved for test/mock evidence are rejected defensively.  The `test`
    /// reservation applies to a whole name segment so that production names
    /// such as `dstack-attest-v0` are not caught by the `attest-` substring.
    pub fn register(&self, verifier: Arc<dyn EvidenceVerifier>) -> Result<(), Denial> {
        let name = verifier.provider();
        crate::validate_text(name)?;
        if name.is_empty() || name.contains("mock") || is_reserved_test_name(name) {
            return Err(Denial::UnsupportedProvider);
        }
        let mut verifiers = self.verifiers.write().map_err(|_| Denial::InternalError)?;
        match verifiers.entry(name.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(verifier);
                Ok(())
            }
            Entry::Occupied(_) => Err(Denial::Malformed),
        }
    }

    pub fn get(&self, provider: &str) -> Result<Arc<dyn EvidenceVerifier>, Denial> {
        self.verifiers
            .read()
            .map_err(|_| Denial::InternalError)?
            .get(provider)
            .cloned()
            .ok_or(Denial::UnsupportedProvider)
    }
}

#[derive(Default)]
pub struct RelationRegistry {
    verifiers: RwLock<HashMap<String, Arc<dyn BindingRelationVerifier>>>,
}

impl RelationRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, verifier: Arc<dyn BindingRelationVerifier>) -> Result<(), Denial> {
        let relation = verifier.relation();
        crate::validate_text(relation)?;
        if relation.is_empty() {
            return Err(Denial::Malformed);
        }
        let mut verifiers = self.verifiers.write().map_err(|_| Denial::InternalError)?;
        match verifiers.entry(relation.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(verifier);
                Ok(())
            }
            Entry::Occupied(_) => Err(Denial::Malformed),
        }
    }

    pub fn get(&self, relation: &str) -> Result<Arc<dyn BindingRelationVerifier>, Denial> {
        self.verifiers
            .read()
            .map_err(|_| Denial::InternalError)?
            .get(relation)
            .cloned()
            .ok_or(Denial::UnsupportedProvider)
    }
}
