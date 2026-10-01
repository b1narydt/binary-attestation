use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{AttestationSubject, Challenge, Denial};

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<u64, Denial>;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Result<u64, Denial> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Denial::ClockUnavailable)
            .and_then(|duration| {
                u64::try_from(duration.as_millis()).map_err(|_| Denial::ClockUnavailable)
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeState {
    Issued,
    Verifying,
    ConsumedAllow,
    ConsumedDeny(Denial),
    Expired,
}

#[derive(Debug, Clone)]
struct StoredChallenge {
    challenge: Challenge,
    state: ChallengeState,
}

/// The default retention period for replay state. It is as conservative as
/// BCAP1's maximum challenge lifetime; deployments with a larger trusted-clock
/// skew must pass that value when constructing their in-memory stores.
pub const DEFAULT_MAX_CLOCK_SKEW_MS: u64 = crate::MAX_CHALLENGE_TTL_MS;

#[derive(Debug, Default)]
struct VerificationPermits {
    total: usize,
    by_subject: HashMap<AttestationSubject, usize>,
}

static VERIFICATION_PERMITS: OnceLock<Mutex<VerificationPermits>> = OnceLock::new();

/// RAII accounting for the process-wide, synchronous verification budget.
pub(crate) struct VerificationPermit {
    subject: AttestationSubject,
}

impl Drop for VerificationPermit {
    fn drop(&mut self) {
        // A poisoned accounting lock fails closed on subsequent acquisition.
        // Drop cannot report that condition, so it must not invent a recovery.
        let Some(pool) = VERIFICATION_PERMITS.get() else {
            return;
        };
        let Ok(mut permits) = pool.lock() else {
            return;
        };
        permits.total = permits.total.saturating_sub(1);
        if let Some(count) = permits.by_subject.get_mut(&self.subject) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                permits.by_subject.remove(&self.subject);
            }
        }
    }
}

/// Atomic one-shot challenge state.  The mutex is intentionally held only for
/// transitions, never while provider verification runs.
#[derive(Debug)]
pub struct ChallengeStore {
    challenges: Mutex<HashMap<String, StoredChallenge>>,
    max_outstanding_per_subject: usize,
    max_outstanding: usize,
    max_clock_skew_ms: u64,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new(4, 10_000)
    }
}

impl ChallengeStore {
    pub const HARD_MAX_OUTSTANDING_PER_SUBJECT: usize = 8;
    pub const HARD_MAX_OUTSTANDING: usize = 100_000;
    pub const HARD_MAX_VERIFICATIONS_PER_SUBJECT: usize = 2;
    pub const HARD_MAX_VERIFICATIONS: usize = 64;
    pub const HARD_MAX_TERMINAL_RECORDS: usize = 100_000;

    /// Creates a bounded store. Values above protocol hard maxima are clamped;
    /// deployments wanting configuration validation may use [`Self::try_new`].
    pub fn new(max_outstanding_per_subject: usize, max_outstanding: usize) -> Self {
        Self::with_max_clock_skew(
            max_outstanding_per_subject,
            max_outstanding,
            DEFAULT_MAX_CLOCK_SKEW_MS,
        )
    }

    /// Configures expiry-plus-skew retention for terminal replay tombstones.
    pub fn with_max_clock_skew(
        max_outstanding_per_subject: usize,
        max_outstanding: usize,
        max_clock_skew_ms: u64,
    ) -> Self {
        Self {
            challenges: Mutex::new(HashMap::new()),
            max_outstanding_per_subject: max_outstanding_per_subject
                .min(Self::HARD_MAX_OUTSTANDING_PER_SUBJECT),
            max_outstanding: max_outstanding.min(Self::HARD_MAX_OUTSTANDING),
            max_clock_skew_ms,
        }
    }

    pub fn try_new(
        max_outstanding_per_subject: usize,
        max_outstanding: usize,
    ) -> Result<Self, Denial> {
        if max_outstanding_per_subject == 0
            || max_outstanding == 0
            || max_outstanding_per_subject > Self::HARD_MAX_OUTSTANDING_PER_SUBJECT
            || max_outstanding > Self::HARD_MAX_OUTSTANDING
        {
            return Err(Denial::ResourceLimit);
        }
        Ok(Self::new(max_outstanding_per_subject, max_outstanding))
    }

    pub fn issue(&self, challenge: Challenge, now_ms: u64) -> Result<(), Denial> {
        challenge.validate()?;
        if challenge.issued_at_ms.get() > now_ms {
            return Err(Denial::Malformed);
        }
        if now_ms >= challenge.expires_at_ms.get() {
            return Err(Denial::ChallengeExpired);
        }
        let mut challenges = self.challenges.lock().map_err(|_| Denial::InternalError)?;
        self.prune_locked(&mut challenges, now_ms);
        if challenges.contains_key(challenge.challenge_id.as_str()) {
            return Err(Denial::Malformed);
        }
        let outstanding = challenges
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    ChallengeState::Issued | ChallengeState::Verifying
                )
            })
            .count();
        let terminal_records = challenges.len().saturating_sub(outstanding);
        let by_subject = challenges
            .values()
            .filter(|record| {
                record.challenge.subject == challenge.subject
                    && matches!(
                        record.state,
                        ChallengeState::Issued | ChallengeState::Verifying
                    )
            })
            .count();
        if outstanding >= self.max_outstanding
            || by_subject >= self.max_outstanding_per_subject
            || terminal_records >= Self::HARD_MAX_TERMINAL_RECORDS
        {
            return Err(Denial::ResourceLimit);
        }
        challenges.insert(
            challenge.challenge_id.as_str().to_owned(),
            StoredChallenge {
                challenge,
                state: ChallengeState::Issued,
            },
        );
        Ok(())
    }

    /// Checks the authenticated and asserted subject before atomically claiming
    /// an issued challenge.  A second matching response sees `challenge_used`
    /// even while the first response is still being verified.
    pub fn begin(
        &self,
        challenge_id: &str,
        authenticated_subject: &AttestationSubject,
        bundle_subject: &AttestationSubject,
        now_ms: u64,
    ) -> Result<Challenge, Denial> {
        let mut challenges = self.challenges.lock().map_err(|_| Denial::InternalError)?;
        self.prune_locked(&mut challenges, now_ms);
        let record = challenges
            .get_mut(challenge_id)
            .ok_or(Denial::ChallengeUnknown)?;
        if &record.challenge.subject != authenticated_subject {
            return Err(Denial::SubjectUnauthenticated);
        }
        if &record.challenge.subject != bundle_subject {
            return Err(Denial::SubjectMismatch);
        }
        match record.state {
            ChallengeState::Issued if now_ms < record.challenge.issued_at_ms.get() => {
                record.state = ChallengeState::ConsumedDeny(Denial::Malformed);
                Err(Denial::Malformed)
            }
            ChallengeState::Issued if now_ms < record.challenge.expires_at_ms.get() => {
                record.state = ChallengeState::Verifying;
                Ok(record.challenge.clone())
            }
            ChallengeState::Issued => {
                record.state = ChallengeState::Expired;
                Err(Denial::ChallengeExpired)
            }
            ChallengeState::Expired => Err(Denial::ChallengeExpired),
            ChallengeState::Verifying
            | ChallengeState::ConsumedAllow
            | ChallengeState::ConsumedDeny(_) => Err(Denial::ChallengeUsed),
        }
    }

    /// Re-checks expiry at the terminal transition.  Every claimed challenge
    /// becomes an allow or a durable denial, never returns to `Issued`.
    pub fn finish(
        &self,
        challenge_id: &str,
        requested: Result<(), Denial>,
        now_ms: u64,
    ) -> Result<(), Denial> {
        let mut challenges = self.challenges.lock().map_err(|_| Denial::InternalError)?;
        let record = challenges
            .get_mut(challenge_id)
            .ok_or(Denial::ChallengeUnknown)?;
        if !matches!(record.state, ChallengeState::Verifying) {
            return Err(Denial::ChallengeUsed);
        }
        let result = if now_ms >= record.challenge.expires_at_ms.get() {
            Err(Denial::ChallengeExpired)
        } else {
            requested
        };
        record.state = match result {
            Ok(()) => ChallengeState::ConsumedAllow,
            Err(denial) => ChallengeState::ConsumedDeny(denial),
        };
        result
    }

    /// Terminates an already claimed challenge when the trusted clock becomes
    /// unavailable. This deliberately does not invent a timestamp.
    pub fn finish_clock_failure(&self, challenge_id: &str) -> Result<(), Denial> {
        let mut challenges = self.challenges.lock().map_err(|_| Denial::InternalError)?;
        let record = challenges
            .get_mut(challenge_id)
            .ok_or(Denial::ChallengeUnknown)?;
        if !matches!(record.state, ChallengeState::Verifying) {
            return Err(Denial::ChallengeUsed);
        }
        record.state = ChallengeState::ConsumedDeny(Denial::ClockUnavailable);
        Err(Denial::ClockUnavailable)
    }

    /// Reserves the fixed protocol concurrency budget after a challenge has
    /// been claimed but before provider work starts. Its RAII guard releases
    /// accounting on every return path, including unwinding.
    pub(crate) fn acquire_verification_permit(
        &self,
        subject: &AttestationSubject,
    ) -> Result<VerificationPermit, Denial> {
        let pool = VERIFICATION_PERMITS.get_or_init(|| Mutex::new(VerificationPermits::default()));
        let mut permits = pool.lock().map_err(|_| Denial::InternalError)?;
        let subject_count = permits.by_subject.get(subject).copied().unwrap_or_default();
        if permits.total >= Self::HARD_MAX_VERIFICATIONS
            || subject_count >= Self::HARD_MAX_VERIFICATIONS_PER_SUBJECT
        {
            return Err(Denial::ResourceLimit);
        }
        permits.total += 1;
        permits
            .by_subject
            .insert(subject.clone(), subject_count + 1);
        Ok(VerificationPermit {
            subject: subject.clone(),
        })
    }

    pub fn state(&self, challenge_id: &str, now_ms: u64) -> Result<ChallengeState, Denial> {
        let mut challenges = self.challenges.lock().map_err(|_| Denial::InternalError)?;
        self.prune_locked(&mut challenges, now_ms);
        let record = challenges
            .get(challenge_id)
            .ok_or(Denial::ChallengeUnknown)?;
        Ok(record.state)
    }

    fn prune_locked(&self, challenges: &mut HashMap<String, StoredChallenge>, now_ms: u64) {
        for record in challenges.values_mut() {
            if matches!(record.state, ChallengeState::Issued)
                && now_ms >= record.challenge.expires_at_ms.get()
            {
                record.state = ChallengeState::Expired;
            }
        }
        challenges.retain(|_, record| {
            matches!(
                record.state,
                ChallengeState::Issued | ChallengeState::Verifying
            ) || now_ms
                < record
                    .challenge
                    .expires_at_ms
                    .get()
                    .saturating_add(self.max_clock_skew_ms)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(value: impl Into<String>) -> AttestationSubject {
        AttestationSubject {
            kind: "did".into(),
            value: value.into(),
        }
    }

    #[test]
    fn verification_permits_enforce_subject_and_process_hard_limits() {
        let store = ChallengeStore::new(1, 1);
        let same_subject = subject("same-subject");
        let first = store
            .acquire_verification_permit(&same_subject)
            .expect("first subject permit");
        let second = store
            .acquire_verification_permit(&same_subject)
            .expect("second subject permit");
        assert!(matches!(
            store.acquire_verification_permit(&same_subject),
            Err(Denial::ResourceLimit)
        ));
        drop((first, second));

        let permits = (0..ChallengeStore::HARD_MAX_VERIFICATIONS)
            .map(|index| {
                store
                    .acquire_verification_permit(&subject(format!("subject-{index}")))
                    .expect("process permit")
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            store.acquire_verification_permit(&subject("one-too-many")),
            Err(Denial::ResourceLimit)
        ));
        drop(permits);
    }
}
