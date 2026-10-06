//! A reusable BRC-100 identity policy: exactly one verified dstack parent and
//! one subject-key child, the challenge subject is the attested key, and the
//! parent's measurements are allowlisted.
//!
//! The policy sees only normalized claims. The core has already required the
//! child to reach the parent through a verified relation edge (its own
//! binding digest is zero), so `subject_binding` names that relation.

use std::collections::BTreeSet;

use binary_attestation_core::{
    B64Url, Challenge, Denial, PolicyDecision, PolicyEvaluator, SignedSecuritySnapshot, U64Decimal,
    VerifiedComponent,
};

use crate::{
    DSTACK_ATTEST_V0_PROVIDER, DSTACK_SUBJECT_KEY_BRC100_RELATION, DSTACK_SUBJECT_KEY_V0_PROVIDER,
};

/// One accepted boot-measurement tuple (lowercase hex of 48-byte registers).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootMeasurements {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
}

#[derive(Debug, Clone)]
pub struct DstackBrc100IdentityPolicy {
    /// Accepted `os_image_hash` values (lowercase hex). Required, non-empty.
    pub(crate) allowed_os_image_hashes: BTreeSet<String>,
    /// Accepted workload compose hashes. Required, non-empty.
    pub(crate) allowed_compose_hashes: BTreeSet<String>,
    pub(crate) allowed_app_ids: Option<BTreeSet<String>>,
    /// Optional pins of the firmware/kernel/initrd registers, the 0.5.x
    /// equivalent of the `dstack-mr` derivation from the OS image.
    pub(crate) allowed_boot_measurements: BTreeSet<BootMeasurements>,
    /// Optional pins of `vm_config_sha256` (the carried, unmeasured config).
    pub(crate) allowed_vm_config_digests: Option<BTreeSet<String>>,
    snapshot: SnapshotBinding,
}

#[derive(Debug, Clone)]
pub(crate) struct SnapshotBinding {
    security_epoch: U64Decimal,
    policy_id: String,
    policy_digest: B64Url,
    trust_digest: B64Url,
}

impl SnapshotBinding {
    pub(crate) fn new(snapshot: &SignedSecuritySnapshot) -> Self {
        Self {
            security_epoch: snapshot.body.security_epoch,
            policy_id: snapshot.body.policy_id.clone(),
            policy_digest: snapshot.body.policy_digest.clone(),
            trust_digest: snapshot.trust_digest.clone(),
        }
    }

    fn matches(&self, snapshot: &SignedSecuritySnapshot) -> bool {
        self.security_epoch == snapshot.body.security_epoch
            && self.policy_id == snapshot.body.policy_id
            && self.policy_digest == snapshot.body.policy_digest
            && self.trust_digest == snapshot.trust_digest
    }
}

impl DstackBrc100IdentityPolicy {
    pub(crate) fn from_snapshot_parts(
        allowed_os_image_hashes: BTreeSet<String>,
        allowed_compose_hashes: BTreeSet<String>,
        allowed_app_ids: Option<BTreeSet<String>>,
        allowed_boot_measurements: BTreeSet<BootMeasurements>,
        allowed_vm_config_digests: Option<BTreeSet<String>>,
        snapshot: &SignedSecuritySnapshot,
    ) -> Self {
        Self {
            allowed_os_image_hashes,
            allowed_compose_hashes,
            allowed_app_ids,
            allowed_boot_measurements,
            allowed_vm_config_digests,
            snapshot: SnapshotBinding::new(snapshot),
        }
    }
}

fn text<'a>(component: &'a VerifiedComponent, key: &str) -> Result<&'a str, Denial> {
    component
        .measurements
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(Denial::Malformed)
}

fn allowed(set: &Option<BTreeSet<String>>, value: &str) -> bool {
    set.as_ref().is_none_or(|set| set.contains(value))
}

impl PolicyEvaluator for DstackBrc100IdentityPolicy {
    fn evaluate(
        &self,
        challenge: &Challenge,
        claims: &[VerifiedComponent],
        snapshot: &SignedSecuritySnapshot,
        _now_ms: u64,
    ) -> Result<PolicyDecision, Denial> {
        if self.allowed_os_image_hashes.is_empty()
            || self.allowed_compose_hashes.is_empty()
            || self
                .allowed_app_ids
                .as_ref()
                .is_some_and(BTreeSet::is_empty)
            || self.allowed_boot_measurements.is_empty()
            || self
                .allowed_vm_config_digests
                .as_ref()
                .is_some_and(BTreeSet::is_empty)
        {
            return Err(Denial::PolicyUnknown);
        }
        if !self.snapshot.matches(snapshot) {
            return Err(Denial::SecurityEpochChanged);
        }
        for claim in claims {
            if claim.provider.contains("mock")
                || claim
                    .provider
                    .split(['-', '_', '.', ':', '/'])
                    .any(|segment| segment.eq_ignore_ascii_case("test"))
            {
                return Err(Denial::UnsupportedProvider);
            }
        }
        let parents = claims
            .iter()
            .filter(|claim| claim.provider == DSTACK_ATTEST_V0_PROVIDER)
            .collect::<Vec<_>>();
        let children = claims
            .iter()
            .filter(|claim| claim.provider == DSTACK_SUBJECT_KEY_V0_PROVIDER)
            .collect::<Vec<_>>();
        if parents.is_empty() || children.is_empty() {
            return Err(Denial::ComponentMissing);
        }
        if parents.len() != 1 || children.len() != 1 || claims.len() != 2 {
            return Err(Denial::PolicyMismatch);
        }
        let (parent, child) = (parents[0], children[0]);
        if parent
            .platform
            .get("profile")
            .and_then(serde_json::Value::as_str)
            != Some(DSTACK_ATTEST_V0_PROVIDER)
            || child
                .platform
                .get("profile")
                .and_then(serde_json::Value::as_str)
                != Some(DSTACK_SUBJECT_KEY_V0_PROVIDER)
        {
            return Err(Denial::UnsupportedProvider);
        }
        if challenge.subject.kind != "brc100-public-key"
            || challenge.subject.value != text(child, "public_key")?
            || text(child, "purpose")? != crate::SUBJECT_KEY_PURPOSE
        {
            return Err(Denial::SubjectMismatch);
        }
        if !self
            .allowed_os_image_hashes
            .contains(text(parent, "os_image_hash")?)
            || !self
                .allowed_compose_hashes
                .contains(text(parent, "compose_hash")?)
            || !allowed(&self.allowed_app_ids, text(parent, "app_id")?)
            || !allowed(
                &self.allowed_vm_config_digests,
                text(parent, "vm_config_sha256")?,
            )
        {
            return Err(Denial::MeasurementMismatch);
        }
        let live = BootMeasurements {
            mrtd: text(parent, "mrtd")?.to_owned(),
            rtmr0: text(parent, "rtmr0")?.to_owned(),
            rtmr1: text(parent, "rtmr1")?.to_owned(),
            rtmr2: text(parent, "rtmr2")?.to_owned(),
        };
        if !self.allowed_boot_measurements.contains(&live) {
            return Err(Denial::MeasurementMismatch);
        }
        Ok(PolicyDecision {
            subject_binding: DSTACK_SUBJECT_KEY_BRC100_RELATION.to_owned(),
            valid_until_ms: parent.valid_until_ms.get().min(child.valid_until_ms.get()),
        })
    }
}
