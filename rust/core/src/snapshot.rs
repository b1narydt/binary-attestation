use std::sync::{Arc, RwLock};

use crate::{Denial, SignedSecuritySnapshot};

/// Strongly-consistent source of the current security epoch.  Provider code
/// must never substitute an instance-local grace cache for this interface.
pub trait SecuritySnapshotStore: Send + Sync {
    fn current(&self) -> Result<Arc<SignedSecuritySnapshot>, Denial>;
}

/// Small in-memory implementation suitable for a single relying-party process
/// and deterministic tests.  Distributed deployments provide the same fence
/// with a linearizable store.
#[derive(Debug)]
pub struct InMemorySnapshotStore {
    current: RwLock<Option<Arc<SignedSecuritySnapshot>>>,
}

impl InMemorySnapshotStore {
    pub const fn new() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    /// Publishes only a strictly increasing epoch.
    pub fn publish(&self, snapshot: SignedSecuritySnapshot) -> Result<(), Denial> {
        snapshot.validate()?;
        let mut current = self.current.write().map_err(|_| Denial::InternalError)?;
        if current
            .as_ref()
            .is_some_and(|previous| previous.body.security_epoch >= snapshot.body.security_epoch)
        {
            return Err(Denial::TrustSnapshotInvalid);
        }
        *current = Some(Arc::new(snapshot));
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
        self.current
            .read()
            .map_err(|_| Denial::InternalError)?
            .clone()
            .ok_or(Denial::TrustSnapshotInvalid)
    }
}
