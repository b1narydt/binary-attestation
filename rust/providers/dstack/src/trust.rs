//! Pinned trust configuration for the `dstack-attest-v0` profile.

use std::collections::BTreeSet;

use binary_attestation_core::Denial;
use der::Decode;
use k256::PublicKey;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

/// Spec §11 "KMS anchor": the pair `(kms_ca_spki, kms_k256_root)` plus an
/// optional `mr-kms` pin. Neither root is ever taken from evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsPins {
    /// DER `SubjectPublicKeyInfo` of the KMS P-256 CA; must equal the
    /// quote-authenticated `key-provider` event id.
    pub ca_spki_der: Vec<u8>,
    /// Compressed SEC1 secp256k1 KMS root that link 1 must recover to.
    pub k256_root: [u8; 33],
    /// Optional `mr-kms` launch-event pin.
    pub mr_kms: Option<[u8; 32]>,
}

impl KmsPins {
    pub(crate) fn validate(&self) -> Result<(), Denial> {
        if self.ca_spki_der.is_empty() || self.ca_spki_der.len() > 4096 {
            return Err(Denial::VerifierUnavailable);
        }
        SubjectPublicKeyInfoOwned::from_der(&self.ca_spki_der)
            .map_err(|_| Denial::VerifierUnavailable)?;
        if !matches!(self.k256_root[0], 2 | 3) {
            return Err(Denial::VerifierUnavailable);
        }
        PublicKey::from_sec1_bytes(&self.k256_root).map_err(|_| Denial::VerifierUnavailable)?;
        Ok(())
    }
}

/// Everything the verifier trusts, pinned at construction.
#[derive(Debug, Clone)]
pub struct DstackTrust {
    /// DER root CA for DCAP; `None` selects Intel's production SGX Root CA.
    pub root_ca_der: Option<Vec<u8>>,
    /// Oldest issue/update time accepted across the evidence-carried Intel
    /// TCB info, QE identity and PCK CRL. The root CRL is excluded because
    /// Intel issues it on a much longer cadence.
    pub min_collateral_issued_ms: u64,
    /// Accepted DCAP TCB statuses (default `UpToDate`).
    pub allowed_tcb_statuses: BTreeSet<String>,
    /// Accepted Intel advisory identifiers. An empty set accepts only reports
    /// with no advisory identifiers.
    pub allowed_advisory_ids: BTreeSet<String>,
    /// Accepted `os-image-hash` launch values (required, non-empty).
    pub allowed_os_image_hashes: BTreeSet<[u8; 32]>,
    /// Accepted workload `compose-hash` values (required, non-empty).
    pub allowed_compose_hashes: BTreeSet<[u8; 32]>,
    /// Optional `app-id` allowlist.
    pub allowed_app_ids: Option<BTreeSet<[u8; 20]>>,
    pub kms: KmsPins,
}

impl DstackTrust {
    pub fn new(kms: KmsPins) -> Self {
        Self {
            root_ca_der: None,
            min_collateral_issued_ms: 0,
            allowed_tcb_statuses: BTreeSet::from(["UpToDate".into()]),
            allowed_advisory_ids: BTreeSet::new(),
            allowed_os_image_hashes: BTreeSet::new(),
            allowed_compose_hashes: BTreeSet::new(),
            allowed_app_ids: None,
            kms,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Denial> {
        self.kms.validate()?;
        if self.allowed_tcb_statuses.is_empty()
            || self.allowed_os_image_hashes.is_empty()
            || self.allowed_compose_hashes.is_empty()
            || self
                .allowed_app_ids
                .as_ref()
                .is_some_and(BTreeSet::is_empty)
            || self.root_ca_der.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(Denial::VerifierUnavailable);
        }
        Ok(())
    }
}
