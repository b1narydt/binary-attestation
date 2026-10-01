use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::{Challenge, ChallengeStore, DEFAULT_MAX_CLOCK_SKEW_MS, Denial, SignedSecuritySnapshot};

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
    max_clock_skew_ms: u64,
}

#[derive(Debug, Default)]
struct SnapshotState {
    current: Option<Arc<SignedSecuritySnapshot>>,
    /// Admission replay tombstones, retained through expiry plus clock skew.
    terminal_allows: HashMap<String, u64>,
}

impl InMemorySnapshotStore {
    pub fn new() -> Self {
        Self::with_max_clock_skew(DEFAULT_MAX_CLOCK_SKEW_MS)
    }

    /// Configures expiry-plus-skew retention for terminal admission records.
    pub fn with_max_clock_skew(max_clock_skew_ms: u64) -> Self {
        Self {
            state: RwLock::new(SnapshotState {
                current: None,
                terminal_allows: HashMap::new(),
            }),
            max_clock_skew_ms,
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
        state.terminal_allows.retain(|_, expires_at_ms| {
            now_ms < expires_at_ms.saturating_add(self.max_clock_skew_ms)
        });
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
        if state
            .terminal_allows
            .contains_key(challenge.challenge_id.as_str())
        {
            return Err(Denial::ChallengeUsed);
        }
        if state.terminal_allows.len() >= ChallengeStore::HARD_MAX_TERMINAL_RECORDS {
            return Err(Denial::ResourceLimit);
        }
        state.terminal_allows.insert(
            challenge.challenge_id.as_str().to_owned(),
            challenge.expires_at_ms.get(),
        );
        Ok(())
    }
}
