use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use crate::{Challenge, Denial, SignedSecuritySnapshot};

/// Strongly-consistent source of the current security epoch.  Provider code
/// must never substitute an instance-local grace cache for this interface.
pub trait SecuritySnapshotStore: Send + Sync {
    fn current(&self) -> Result<Arc<SignedSecuritySnapshot>, Denial>;

    /// Atomically commits a terminal allow decision on the shared
    /// epoch+terminal-decision fence. Implementations must check the exact
    /// epoch/policy/trust/time in that transaction. The caller mirrors a
    /// successful commit into its local challenge cache only afterwards.
    fn terminal_fence(&self, challenge: &Challenge, now_ms: u64) -> Result<(), Denial>;
}

/// Small in-memory implementation suitable for a single relying-party process
/// and deterministic tests.  Distributed deployments provide the same fence
/// with a linearizable store.
#[derive(Debug)]
pub struct InMemorySnapshotStore {
    state: RwLock<SnapshotState>,
}

#[derive(Debug, Default)]
struct SnapshotState {
    current: Option<Arc<SignedSecuritySnapshot>>,
    terminal_allows: HashSet<String>,
}

impl InMemorySnapshotStore {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(SnapshotState {
                current: None,
                terminal_allows: HashSet::new(),
            }),
        }
    }

    /// Publishes only a strictly increasing epoch.
    pub fn publish(&self, snapshot: SignedSecuritySnapshot) -> Result<(), Denial> {
        snapshot.validate()?;
        let mut state = self.state.write().map_err(|_| Denial::InternalError)?;
        if state
            .current
            .as_ref()
            .is_some_and(|previous| previous.body.security_epoch >= snapshot.body.security_epoch)
        {
            return Err(Denial::TrustSnapshotInvalid);
        }
        state.current = Some(Arc::new(snapshot));
        Ok(())
    }
}

impl Default for InMemorySnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecuritySnapshotStore for InMemorySnapshotStore {
    fn current(&self) -> Result<Arc<SignedSecuritySnapshot>, Denial> {
        self.state
            .read()
            .map_err(|_| Denial::InternalError)?
            .current
            .clone()
            .ok_or(Denial::TrustSnapshotInvalid)
    }

    fn terminal_fence(&self, challenge: &Challenge, now_ms: u64) -> Result<(), Denial> {
        // Publishing and committing an allow use this same exclusive fence.
        // Thus their commits have one total order, matching the distributed
        // SecurityDomainStore contract without pretending a remote commit and
        // local cache write are one transaction.
        let mut state = self.state.write().map_err(|_| Denial::InternalError)?;
        // `expiresAtMs` is exclusive. A shared allow record must never be
        // committed for a challenge that the local lifecycle will deny.
        if now_ms >= challenge.expires_at_ms.get() {
            return Err(Denial::ChallengeExpired);
        }
        let decision = state
            .current
            .as_ref()
            .ok_or(Denial::TrustSnapshotInvalid)
            .and_then(|snapshot| {
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
                Ok(())
            });
        decision?;
        if !state
            .terminal_allows
            .insert(challenge.challenge_id.as_str().to_owned())
        {
            return Err(Denial::ChallengeUsed);
        }
        Ok(())
    }
}
