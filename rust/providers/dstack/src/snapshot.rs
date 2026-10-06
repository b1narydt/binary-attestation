//! Canonical snapshot artifact for one complete `dstack-attest-v0` verifier,
//! relation and policy configuration.

use std::collections::BTreeSet;

use binary_attestation_core::{
    B64Url, Denial, MAX_BUNDLE_BYTES, ProviderPolicyArtifact, SignedSecuritySnapshot, jcs_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BootMeasurements, DSTACK_ATTEST_V0_PROVIDER, DstackAttestV0Verifier,
    DstackBrc100IdentityPolicy, DstackSubjectKeyBrc100Relation, DstackSubjectKeyV0Verifier,
    DstackTrust, KmsPins, PinnedCollateral, hex,
};

pub const DSTACK_POLICY_ARTIFACT_MEDIA_TYPE: &str =
    "application/vnd.binary.dstack-policy+json;version=1";
pub const DSTACK_POLICY_ARTIFACT_CANONICALIZATION: &str = "rfc8785-jcs";

/// DCAP root selected by the snapshot. Production Intel root bytes come from
/// the exactly pinned `dcap-qvl` crate; a custom root carries its exact DER.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DcapRootV1 {
    IntelSgxRootCaProd,
    CustomDer { der: B64Url },
}

/// Complete provider trust and MPC identity policy committed by one snapshot
/// artifact. Required arrays are fail-closed: empty collateral, TCB statuses,
/// OS images, compose hashes or boot tuples make plugin construction fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DstackPolicyArtifactV1 {
    pub profile: String,
    pub dcap_root: DcapRootV1,
    /// Exact JSON bytes accepted by [`PinnedCollateral::from_json`].
    pub collateral_json: Vec<B64Url>,
    pub allowed_tcb_statuses: Vec<String>,
    /// Empty means that the verified report must carry no advisory IDs.
    pub allowed_advisory_ids: Vec<String>,
    pub allowed_os_image_hashes: Vec<String>,
    pub allowed_compose_hashes: Vec<String>,
    /// Empty means any quote-authenticated app ID; the subject relation still
    /// binds its GetKey chain to the exact app ID from the parent.
    pub allowed_app_ids: Vec<String>,
    pub kms_ca_spki_der: B64Url,
    pub kms_k256_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mr_kms: Option<String>,
    pub allowed_boot_measurements: Vec<BootMeasurements>,
    /// Empty means the unmeasured VM config is not separately pinned.
    pub allowed_vm_config_digests: Vec<String>,
}

impl DstackPolicyArtifactV1 {
    /// Wraps these canonical bytes as a snapshot provider artifact.
    pub fn to_provider_artifact(
        &self,
        artifact_id: impl Into<String>,
    ) -> Result<ProviderPolicyArtifact, Denial> {
        let content = jcs_bytes(self)?;
        Ok(ProviderPolicyArtifact {
            artifact_id: artifact_id.into(),
            provider: DSTACK_ATTEST_V0_PROVIDER.to_owned(),
            media_type: DSTACK_POLICY_ARTIFACT_MEDIA_TYPE.to_owned(),
            canonicalization: DSTACK_POLICY_ARTIFACT_CANONICALIZATION.to_owned(),
            digest: B64Url::from_bytes(&Sha256::digest(&content)),
            content: B64Url::from_bytes(&content),
        })
    }
}

/// Snapshot-bound plugins registered together in one [`binary_attestation_core::CoreVerifier`].
pub struct DstackSnapshotPlugins {
    pub parent: DstackAttestV0Verifier,
    pub child: DstackSubjectKeyV0Verifier,
    pub relation: DstackSubjectKeyBrc100Relation,
    pub policy: DstackBrc100IdentityPolicy,
}

impl DstackSnapshotPlugins {
    /// Builds every dstack trust decision from the one canonical artifact in
    /// `snapshot`. A caller cannot combine a new `trustDigest` with old local
    /// verifier pins through this API.
    pub fn from_snapshot(snapshot: &SignedSecuritySnapshot) -> Result<Self, Denial> {
        snapshot.validate()?;
        let mut matching = snapshot.body.provider_artifacts.iter().filter(|artifact| {
            artifact.provider == DSTACK_ATTEST_V0_PROVIDER
                && artifact.media_type == DSTACK_POLICY_ARTIFACT_MEDIA_TYPE
        });
        let wrapped = matching.next().ok_or(Denial::PolicyUnknown)?;
        if matching.next().is_some()
            || wrapped.canonicalization != DSTACK_POLICY_ARTIFACT_CANONICALIZATION
        {
            return Err(Denial::Malformed);
        }
        let content = wrapped.content.decode_with_limit(MAX_BUNDLE_BYTES)?;
        let artifact: DstackPolicyArtifactV1 =
            serde_json::from_slice(&content).map_err(|_| Denial::Malformed)?;
        if jcs_bytes(&artifact)? != content || artifact.profile != DSTACK_ATTEST_V0_PROVIDER {
            return Err(Denial::Malformed);
        }

        let kms = KmsPins {
            ca_spki_der: artifact.kms_ca_spki_der.decode_with_limit(4096)?,
            k256_root: lower_hex_array::<33>(&artifact.kms_k256_root)?,
            mr_kms: artifact
                .mr_kms
                .as_deref()
                .map(lower_hex_array::<32>)
                .transpose()?,
        };
        let mut trust = DstackTrust::new(kms.clone());
        trust.root_ca_der = match &artifact.dcap_root {
            DcapRootV1::IntelSgxRootCaProd => None,
            DcapRootV1::CustomDer { der } => Some(der.decode_with_limit(4096)?),
        };
        trust.collateral = unique_collateral(&artifact.collateral_json)?;
        trust.allowed_tcb_statuses = unique_text(&artifact.allowed_tcb_statuses, false)?;
        trust.allowed_advisory_ids = unique_text(&artifact.allowed_advisory_ids, true)?;
        trust.allowed_os_image_hashes = unique_hex::<32>(&artifact.allowed_os_image_hashes, false)?;
        trust.allowed_compose_hashes = unique_hex::<32>(&artifact.allowed_compose_hashes, false)?;
        trust.allowed_app_ids = optional_hex::<20>(&artifact.allowed_app_ids)?;

        let allowed_boot_measurements = unique_boot(&artifact.allowed_boot_measurements)?;
        let allowed_vm_config_digests =
            optional_canonical_hex::<32>(&artifact.allowed_vm_config_digests)?;
        let policy = DstackBrc100IdentityPolicy::from_snapshot_parts(
            canonical_hex_set::<32>(&artifact.allowed_os_image_hashes, false)?,
            canonical_hex_set::<32>(&artifact.allowed_compose_hashes, false)?,
            optional_canonical_hex::<20>(&artifact.allowed_app_ids)?,
            allowed_boot_measurements,
            allowed_vm_config_digests,
            snapshot,
        );

        Ok(Self {
            parent: DstackAttestV0Verifier::new(trust)?,
            child: DstackSubjectKeyV0Verifier::new(),
            relation: DstackSubjectKeyBrc100Relation::new(kms)?,
            policy,
        })
    }
}

fn lower_hex_array<const N: usize>(value: &str) -> Result<[u8; N], Denial> {
    hex::decode_lower_array(value).ok_or(Denial::Malformed)
}

fn unique_text(values: &[String], allow_empty: bool) -> Result<BTreeSet<String>, Denial> {
    if (!allow_empty && values.is_empty())
        || values.iter().any(|value| {
            value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control)
        })
    {
        return Err(Denial::VerifierUnavailable);
    }
    let set = values.iter().cloned().collect::<BTreeSet<_>>();
    if set.len() != values.len() {
        return Err(Denial::Malformed);
    }
    Ok(set)
}

fn unique_hex<const N: usize>(
    values: &[String],
    allow_empty: bool,
) -> Result<BTreeSet<[u8; N]>, Denial> {
    if !allow_empty && values.is_empty() {
        return Err(Denial::VerifierUnavailable);
    }
    let set = values
        .iter()
        .map(|value| lower_hex_array(value))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if set.len() != values.len() {
        return Err(Denial::Malformed);
    }
    Ok(set)
}

fn optional_hex<const N: usize>(values: &[String]) -> Result<Option<BTreeSet<[u8; N]>>, Denial> {
    if values.is_empty() {
        Ok(None)
    } else {
        unique_hex(values, false).map(Some)
    }
}

fn canonical_hex_set<const N: usize>(
    values: &[String],
    allow_empty: bool,
) -> Result<BTreeSet<String>, Denial> {
    unique_hex::<N>(values, allow_empty)?;
    Ok(values.iter().cloned().collect())
}

fn optional_canonical_hex<const N: usize>(
    values: &[String],
) -> Result<Option<BTreeSet<String>>, Denial> {
    if values.is_empty() {
        Ok(None)
    } else {
        canonical_hex_set::<N>(values, false).map(Some)
    }
}

fn unique_boot(values: &[BootMeasurements]) -> Result<BTreeSet<BootMeasurements>, Denial> {
    if values.is_empty() {
        return Err(Denial::VerifierUnavailable);
    }
    for boot in values {
        for value in [&boot.mrtd, &boot.rtmr0, &boot.rtmr1, &boot.rtmr2] {
            lower_hex_array::<48>(value)?;
        }
    }
    let set = values.iter().cloned().collect::<BTreeSet<_>>();
    if set.len() != values.len() {
        return Err(Denial::Malformed);
    }
    Ok(set)
}

fn unique_collateral(values: &[B64Url]) -> Result<Vec<PinnedCollateral>, Denial> {
    if values.is_empty() {
        return Err(Denial::VerifierUnavailable);
    }
    let mut digests = BTreeSet::new();
    let mut collateral = Vec::with_capacity(values.len());
    for value in values {
        let bytes = value.decode_with_limit(MAX_BUNDLE_BYTES)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if !digests.insert(digest) {
            return Err(Denial::Malformed);
        }
        collateral.push(PinnedCollateral::from_json(&bytes)?);
    }
    Ok(collateral)
}
