//! Pinned Intel DCAP collateral, loaded once from a JSON document and used
//! offline. The document has `dcap-qvl`'s `QuoteCollateralV3` field names with
//! the binary fields hex-encoded (the human-readable form PCCS captures and
//! newer `dcap-qvl` releases emit):
//!
//! ```json
//! {
//!   "pck_crl_issuer_chain": "<PEM>", "root_ca_crl": "<hex DER>", "pck_crl": "<hex DER>",
//!   "tcb_info_issuer_chain": "<PEM>", "tcb_info": "<JSON>", "tcb_info_signature": "<hex>",
//!   "qe_identity_issuer_chain": "<PEM>", "qe_identity": "<JSON>", "qe_identity_signature": "<hex>",
//!   "pck_certificate_chain": "<PEM, optional>"
//! }
//! ```

use base64::{Engine as _, engine::general_purpose::STANDARD};
use binary_attestation_core::Denial;
use dcap_qvl::QuoteCollateralV3;
use der::Decode;
use serde::{Deserialize, Serialize};
use x509_cert::{Certificate, crl::CertificateList, time::Time};

use crate::hex;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PinnedCollateralJson {
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
    tcb_info_signature: String,
    qe_identity_issuer_chain: String,
    qe_identity: String,
    qe_identity_signature: String,
    #[serde(default)]
    pck_certificate_chain: Option<String>,
}

#[derive(Deserialize)]
struct Dated {
    #[serde(rename = "issueDate")]
    issue_date: String,
    #[serde(rename = "nextUpdate")]
    next_update: String,
    #[serde(default)]
    fmspc: Option<String>,
}

/// Collateral for one FMSPC with its validity window precomputed.
#[derive(Clone)]
pub struct PinnedCollateral {
    inner: QuoteCollateralV3,
    fmspc: String,
    issued_at_ms: u64,
    not_before_ms: u64,
    not_after_ms: u64,
}

impl core::fmt::Debug for PinnedCollateral {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinnedCollateral")
            .field("fmspc", &self.fmspc)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("not_before_ms", &self.not_before_ms)
            .field("not_after_ms", &self.not_after_ms)
            .finish_non_exhaustive()
    }
}

impl PinnedCollateral {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Denial> {
        let json: PinnedCollateralJson =
            serde_json::from_slice(bytes).map_err(|_| Denial::Malformed)?;
        let decode = |value: &str| hex::decode_any(value).ok_or(Denial::Malformed);
        Self::from_quote_collateral(QuoteCollateralV3 {
            pck_crl_issuer_chain: json.pck_crl_issuer_chain,
            root_ca_crl: decode(&json.root_ca_crl)?,
            pck_crl: decode(&json.pck_crl)?,
            tcb_info_issuer_chain: json.tcb_info_issuer_chain,
            tcb_info: json.tcb_info,
            tcb_info_signature: decode(&json.tcb_info_signature)?,
            qe_identity_issuer_chain: json.qe_identity_issuer_chain,
            qe_identity: json.qe_identity,
            qe_identity_signature: decode(&json.qe_identity_signature)?,
            pck_certificate_chain: json.pck_certificate_chain,
        })
    }

    pub fn from_quote_collateral(inner: QuoteCollateralV3) -> Result<Self, Denial> {
        let tcb = dated(&inner.tcb_info, "tcbInfo")?;
        let qe = dated(&inner.qe_identity, "enclaveIdentity")?;
        let fmspc = tcb
            .fmspc
            .as_deref()
            .filter(|value| value.len() == 12 && hex::decode_any(value).is_some())
            .ok_or(Denial::Malformed)?
            .to_ascii_uppercase();
        let issued_at_ms = rfc3339_ms(&tcb.issue_date)?;
        let mut windows = vec![
            (issued_at_ms, rfc3339_ms(&tcb.next_update)?),
            (rfc3339_ms(&qe.issue_date)?, rfc3339_ms(&qe.next_update)?),
            crl_window(&inner.root_ca_crl)?,
            crl_window(&inner.pck_crl)?,
        ];
        if let Some(chain) = &inner.pck_certificate_chain {
            let leaf = Certificate::from_der(&first_pem_certificate(chain)?)
                .map_err(|_| Denial::Malformed)?;
            windows.push((
                time_ms(&leaf.tbs_certificate.validity.not_before)?,
                time_ms(&leaf.tbs_certificate.validity.not_after)?,
            ));
        }
        let not_before_ms = windows.iter().map(|w| w.0).max().ok_or(Denial::Malformed)?;
        let not_after_ms = windows.iter().map(|w| w.1).min().ok_or(Denial::Malformed)?;
        if not_before_ms >= not_after_ms {
            return Err(Denial::EndorsementsStale);
        }
        Ok(Self {
            inner,
            fmspc,
            issued_at_ms,
            not_before_ms,
            not_after_ms,
        })
    }

    pub fn to_json(&self) -> Result<Vec<u8>, Denial> {
        serde_json::to_vec(&PinnedCollateralJson {
            pck_crl_issuer_chain: self.inner.pck_crl_issuer_chain.clone(),
            root_ca_crl: hex::encode(&self.inner.root_ca_crl),
            pck_crl: hex::encode(&self.inner.pck_crl),
            tcb_info_issuer_chain: self.inner.tcb_info_issuer_chain.clone(),
            tcb_info: self.inner.tcb_info.clone(),
            tcb_info_signature: hex::encode(&self.inner.tcb_info_signature),
            qe_identity_issuer_chain: self.inner.qe_identity_issuer_chain.clone(),
            qe_identity: self.inner.qe_identity.clone(),
            qe_identity_signature: hex::encode(&self.inner.qe_identity_signature),
            pck_certificate_chain: self.inner.pck_certificate_chain.clone(),
        })
        .map_err(|_| Denial::Malformed)
    }

    /// Uppercase-hex FMSPC this collateral is for.
    pub fn fmspc(&self) -> &str {
        &self.fmspc
    }

    /// Intel TCB-info `issueDate`, used by an Atlas-set rollback floor.
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Latest `issueDate` / `thisUpdate` / `notBefore` across the documents.
    pub fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }

    /// Earliest `nextUpdate` / `notAfter` across the documents: the hard cap
    /// on any component validity derived from this collateral.
    pub fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    pub fn is_valid_at(&self, now_ms: u64) -> bool {
        self.not_before_ms <= now_ms && now_ms < self.not_after_ms
    }

    pub(crate) fn inner(&self) -> &QuoteCollateralV3 {
        &self.inner
    }

    /// DER of the pinned PCK leaf certificate, when the collateral carries
    /// the chain.
    pub(crate) fn pck_leaf_der(&self) -> Result<Option<Vec<u8>>, Denial> {
        self.inner
            .pck_certificate_chain
            .as_deref()
            .map(first_pem_certificate)
            .transpose()
    }
}

fn dated(document: &str, wrapper: &str) -> Result<Dated, Denial> {
    let value: serde_json::Value = serde_json::from_str(document).map_err(|_| Denial::Malformed)?;
    let body = value.get(wrapper).unwrap_or(&value);
    serde_json::from_value(body.clone()).map_err(|_| Denial::Malformed)
}

fn rfc3339_ms(value: &str) -> Result<u64, Denial> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value).map_err(|_| Denial::Malformed)?;
    let secs = u64::try_from(parsed.timestamp()).map_err(|_| Denial::Malformed)?;
    secs.checked_mul(1_000).ok_or(Denial::Malformed)
}

fn time_ms(time: &Time) -> Result<u64, Denial> {
    u64::try_from(time.to_unix_duration().as_millis()).map_err(|_| Denial::Malformed)
}

/// DER of the first `CERTIFICATE` block in a PEM bundle (the PCK leaf).
pub(crate) fn first_pem_certificate(pem: &str) -> Result<Vec<u8>, Denial> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN).ok_or(Denial::Malformed)? + BEGIN.len();
    let end = pem[start..].find(END).ok_or(Denial::Malformed)? + start;
    let body = pem[start..end]
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<u8>>();
    STANDARD.decode(body).map_err(|_| Denial::Malformed)
}

fn crl_window(der: &[u8]) -> Result<(u64, u64), Denial> {
    let crl = CertificateList::from_der(der).map_err(|_| Denial::Malformed)?;
    let next_update = crl.tbs_cert_list.next_update.ok_or(Denial::Malformed)?;
    Ok((
        time_ms(&crl.tbs_cert_list.this_update)?,
        time_ms(&next_update)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_and_rejections() {
        assert_eq!(rfc3339_ms("2026-11-05T00:26:11Z"), Ok(1_793_838_371_000));
        assert_eq!(rfc3339_ms("2026-11-05"), Err(Denial::Malformed));
        assert_eq!(rfc3339_ms("1960-01-01T00:00:00Z"), Err(Denial::Malformed));
        assert_eq!(PinnedCollateral::from_json(b"{}"), Err(Denial::Malformed));
        assert_eq!(PinnedCollateral::from_json(b"[]"), Err(Denial::Malformed));
    }

    impl PartialEq for PinnedCollateral {
        fn eq(&self, other: &Self) -> bool {
            self.fmspc == other.fmspc
        }
    }
}
