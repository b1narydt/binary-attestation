//! The `dstack-attest-v0` evidence verifier.

use std::collections::BTreeMap;

use binary_attestation_core::{
    B64Url, Denial, EvidenceComponent, EvidenceVerifier, MAX_COMPONENT_ENDORSEMENTS,
    MAX_COMPONENT_EVIDENCE, U64Decimal, VerifiedComponent, constant_time_eq,
};
use dcap_qvl::verify::QuoteVerifier;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    DstackTrust,
    events::{
        LaunchEvents, RUNTIME_EVENT_IMR, RUNTIME_EVENT_TYPE, parse_launch_events, replay_rtmr3,
        runtime_event_digest,
    },
    hex,
    scale::LegacyAttestationV0,
};

pub const DSTACK_ATTEST_V0_PROVIDER: &str = "dstack-attest-v0";
/// Raw `/Attest` bytes: the legacy SCALE V0 `VersionedAttestation`.
pub const DSTACK_ATTEST_V0_MEDIA_TYPE: &str = "application/vnd.dstack.attestation.scale-v0";

/// Verifies dstack 0.5.x `/Attest` evidence against pinned trust. See the
/// crate documentation for the exact order of checks.
pub struct DstackAttestV0Verifier {
    trust: DstackTrust,
    quote_verifier: QuoteVerifier,
}

#[derive(Deserialize)]
struct VmConfigView {
    os_image_hash: Option<String>,
}

impl DstackAttestV0Verifier {
    /// Refuses (`verifier_unavailable`) any trust set that could not produce a
    /// fail-closed verdict: no collateral, no TCB allowlist, no allowed OS
    /// image, or unusable KMS pins.
    pub fn new(trust: DstackTrust) -> Result<Self, Denial> {
        trust.validate()?;
        let quote_verifier = match &trust.root_ca_der {
            Some(der) => QuoteVerifier::new(der.clone()),
            None => QuoteVerifier::new_prod(),
        };
        Ok(Self {
            trust,
            quote_verifier,
        })
    }

    pub fn trust(&self) -> &DstackTrust {
        &self.trust
    }

    fn verify_inner(
        &self,
        component: &EvidenceComponent,
        expected_binding: [u8; 64],
        now_ms: u64,
    ) -> Result<VerifiedComponent, Denial> {
        // 1. Component shape.
        if component.provider != DSTACK_ATTEST_V0_PROVIDER
            || component.media_type != DSTACK_ATTEST_V0_MEDIA_TYPE
        {
            return Err(Denial::Malformed);
        }
        let evidence = component
            .evidence
            .decode_with_limit(MAX_COMPONENT_EVIDENCE)?;
        let evidence_digest: [u8; 32] = Sha256::digest(&evidence).into();

        // 2. Bounded decode.
        let envelope = LegacyAttestationV0::decode(&evidence)?;

        // 3. Structural launch checks (cheap, before any crypto).
        let launch_events = launch_sequence(&envelope)?;
        let launch = parse_launch_events(&launch_events)?;
        let vm_config: VmConfigView =
            serde_json::from_str(&envelope.config).map_err(|_| Denial::Malformed)?;

        // 4. Envelope binding field.
        if !constant_time_eq(&envelope.report_data, &expected_binding) {
            return Err(Denial::BindingMismatch);
        }

        // 5. Evidence-carried collateral and DCAP.
        let parsed =
            dcap_qvl::quote::Quote::parse(&envelope.quote).map_err(|_| Denial::Malformed)?;
        let fmspc =
            hex::encode(&dcap_qvl::intel::quote_fmspc(&parsed).map_err(|_| Denial::Malformed)?)
                .to_ascii_uppercase();
        let collateral_bytes = component
            .endorsements
            .as_ref()
            .ok_or(Denial::EndorsementsMissing)?
            .decode_with_limit(MAX_COMPONENT_ENDORSEMENTS)?;
        let collateral = crate::PinnedCollateral::from_json(&collateral_bytes)?;
        if collateral.fmspc() != fmspc {
            return Err(Denial::EndorsementsMissing);
        }
        if collateral.issued_at_ms() < self.trust.min_collateral_issued_ms {
            return Err(Denial::EndorsementsStale);
        }
        // DCAP verifies the quote chain to the policy-selected root. Require
        // the quote to carry the collateral's leaf so evidence cannot name a
        // different platform certificate.
        if let Some(pinned_leaf) = collateral.pck_leaf_der()? {
            let embedded = parsed.raw_cert_chain().map_err(|_| Denial::Malformed)?;
            let embedded_pem = std::str::from_utf8(embedded).map_err(|_| Denial::Malformed)?;
            let embedded_leaf = crate::collateral::first_pem_certificate(embedded_pem)?;
            if !constant_time_eq(&embedded_leaf, &pinned_leaf) {
                return Err(Denial::EndorsementsMissing);
            }
        }
        if !collateral.is_valid_at(now_ms) {
            return Err(Denial::EndorsementsStale);
        }
        let report = self
            .quote_verifier
            .verify(&envelope.quote, collateral.inner(), now_ms / 1_000)
            .map_err(|error| classify_dcap_error(&error))?;
        let td = report.report.as_td10().ok_or(Denial::UnsupportedProvider)?;

        // 6. Authenticated binding and TCB posture.
        if !constant_time_eq(&td.report_data, &expected_binding) {
            return Err(Denial::BindingMismatch);
        }
        if !tcb_posture_allowed(&self.trust, &report.status, &report.advisory_ids) {
            return Err(Denial::TcbDisallowed);
        }

        // 7. RTMR3 replay from recomputed digests.
        let replayed = replay_rtmr3(
            launch_events
                .iter()
                .map(|(event, payload)| runtime_event_digest(event, payload)),
        );
        if !constant_time_eq(&replayed, &td.rt_mr3) {
            return Err(Denial::MeasurementMismatch);
        }

        // 8. Measurement pins.
        let mut expected_config_id = [0u8; 48];
        expected_config_id[0] = 0x01;
        expected_config_id[1..33].copy_from_slice(&launch.compose_hash);
        if !constant_time_eq(&td.mr_config_id, &expected_config_id) {
            return Err(Denial::MeasurementMismatch);
        }
        if !constant_time_eq(&launch.key_provider_id, &self.trust.kms.ca_spki_der) {
            return Err(Denial::RootUntrusted);
        }
        if let Some(mr_kms) = &self.trust.kms.mr_kms
            && !constant_time_eq(mr_kms, &launch.mr_kms)
        {
            return Err(Denial::RootUntrusted);
        }
        if !self
            .trust
            .allowed_os_image_hashes
            .contains(&launch.os_image_hash)
        {
            return Err(Denial::MeasurementMismatch);
        }
        if !self
            .trust
            .allowed_compose_hashes
            .contains(&launch.compose_hash)
            || self
                .trust
                .allowed_app_ids
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&launch.app_id))
        {
            return Err(Denial::MeasurementMismatch);
        }
        // The carried vm_config is not quote-measured on 0.5.x; it may only
        // agree with the measured launch value, and its digest is exposed so a
        // policy can pin the whole document.
        if vm_config.os_image_hash.as_deref() != Some(hex::encode(&launch.os_image_hash).as_str()) {
            return Err(Denial::MeasurementMismatch);
        }

        // 9. Normalize.
        let td_debug = td.td_attributes[0] & 0x01 != 0;
        if td_debug {
            return Err(Denial::DebugMode);
        }
        Ok(VerifiedComponent {
            component_id: component.component_id.clone(),
            provider: DSTACK_ATTEST_V0_PROVIDER.to_owned(),
            evidence_digest: B64Url::from_bytes(&evidence_digest),
            binding_digest: B64Url::from_bytes(&expected_binding),
            platform: BTreeMap::from([
                ("tee".to_owned(), "tdx".into()),
                ("profile".to_owned(), DSTACK_ATTEST_V0_PROVIDER.into()),
                ("quote_version".to_owned(), parsed.header.version.into()),
                ("fmspc".to_owned(), fmspc.clone().into()),
                ("key_provider_name".to_owned(), "kms".into()),
                ("td_debug".to_owned(), td_debug.into()),
            ]),
            measurements: measurements(td, &launch, &envelope.config),
            tcb: BTreeMap::from([
                ("status".to_owned(), report.status.clone().into()),
                ("fmspc".to_owned(), fmspc.into()),
            ]),
            advisories: report.advisory_ids.clone(),
            valid_until_ms: decimal(collateral.not_after_ms())?,
        })
    }
}

impl EvidenceVerifier for DstackAttestV0Verifier {
    fn provider(&self) -> &'static str {
        DSTACK_ATTEST_V0_PROVIDER
    }

    fn verify(
        &self,
        component: &EvidenceComponent,
        expected_binding: [u8; 64],
        now_ms: u64,
    ) -> Result<VerifiedComponent, Denial> {
        self.verify_inner(component, expected_binding, now_ms)
    }
}

/// The RTMR3 launch sequence. The 0.5.9 envelope carries it twice: as the
/// `imr == 3` entries of the TDX event log and as the `RuntimeEvent` list.
/// Both must agree exactly; only the names and payloads are used.
fn launch_sequence(envelope: &LegacyAttestationV0) -> Result<Vec<(String, Vec<u8>)>, Denial> {
    let mut from_tdx = Vec::new();
    for event in &envelope.tdx_events {
        if event.imr > RUNTIME_EVENT_IMR {
            return Err(Denial::Malformed);
        }
        if event.imr == RUNTIME_EVENT_IMR {
            if event.event_type != RUNTIME_EVENT_TYPE {
                return Err(Denial::Malformed);
            }
            from_tdx.push((event.event.clone(), event.event_payload.clone()));
        }
    }
    let from_runtime = envelope
        .runtime_events
        .iter()
        .map(|event| (event.event.clone(), event.payload.clone()))
        .collect::<Vec<_>>();
    if from_tdx != from_runtime {
        return Err(Denial::Malformed);
    }
    Ok(from_runtime)
}

fn measurements(
    td: &dcap_qvl::quote::TDReport10,
    launch: &LaunchEvents,
    config: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut out = BTreeMap::new();
    let mut put = |key: &str, bytes: &[u8]| {
        out.insert(
            key.to_owned(),
            serde_json::Value::String(hex::encode(bytes)),
        );
    };
    put("mrtd", &td.mr_td);
    put("rtmr0", &td.rt_mr0);
    put("rtmr1", &td.rt_mr1);
    put("rtmr2", &td.rt_mr2);
    put("rtmr3", &td.rt_mr3);
    put("mr_config_id", &td.mr_config_id);
    put("compose_hash", &launch.compose_hash);
    put("app_id", &launch.app_id);
    put(
        "instance_id",
        launch.instance_id.as_ref().map_or(&[][..], |id| &id[..]),
    );
    put("os_image_hash", &launch.os_image_hash);
    put("mr_kms", &launch.mr_kms);
    put("key_provider_id", &launch.key_provider_id);
    put("storage_fs", &launch.storage_fs);
    put("vm_config_sha256", &Sha256::digest(config.as_bytes()));
    out
}

fn decimal(value: u64) -> Result<U64Decimal, Denial> {
    U64Decimal::new(&value.to_string())
}

fn tcb_posture_allowed(trust: &DstackTrust, status: &str, advisory_ids: &[String]) -> bool {
    trust.allowed_tcb_statuses.contains(status)
        && advisory_ids
            .iter()
            .all(|advisory| trust.allowed_advisory_ids.contains(advisory))
}

/// Maps `dcap-qvl`'s stringly errors onto §10 denial classes. The default is
/// `signature_invalid` (authentication failed) rather than anything softer.
fn classify_dcap_error(error: &anyhow::Error) -> Denial {
    let text = format!("{error:#}");
    let has = |needle: &str| text.contains(needle);
    if has("Revoked") || has("revoked") {
        Denial::Revoked
    } else if has("expired") || has("Expired") || has("in the future") || has("date") {
        Denial::EndorsementsStale
    } else if has("TCB status is invalid") || has("No matching TCB level") || has("below minimum") {
        Denial::TcbDisallowed
    } else if has("Debug mode") {
        Denial::DebugMode
    } else if has("Fmspc mismatch") {
        Denial::EndorsementsMissing
    } else if has("ignature is invalid") || has("hash mismatch") || has("MRSIGNER") {
        Denial::SignatureInvalid
    } else if has("Failed to decode")
        || has("Unsupported")
        || has("Unknown QE vendor")
        || has("too short")
        || has("Failed to parse")
    {
        Denial::Malformed
    } else if has("root ca")
        || has("ertificate")
        || has("chain")
        || has("CRL")
        || has("UnknownIssuer")
        || has("Issuer")
    {
        Denial::RootUntrusted
    } else {
        Denial::SignatureInvalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcap_error_classes() {
        let classify = |text: &str| classify_dcap_error(&anyhow::anyhow!("{text}"));
        assert_eq!(classify("TCBInfo expired"), Denial::EndorsementsStale);
        assert_eq!(classify("CertRevoked"), Denial::Revoked);
        assert_eq!(classify("TCB status is invalid: Revoked"), Denial::Revoked);
        assert_eq!(
            classify("TCB status is invalid: OutOfDate"),
            Denial::TcbDisallowed
        );
        assert_eq!(
            classify("ISV enclave report signature is invalid"),
            Denial::SignatureInvalid
        );
        assert_eq!(
            classify("Failed to extract PCK certificates from quote: bad"),
            Denial::RootUntrusted
        );
        assert_eq!(classify("Debug mode is enabled"), Denial::DebugMode);
        assert_eq!(classify("something else"), Denial::SignatureInvalid);
    }

    #[test]
    fn tcb_posture_requires_every_advisory_to_be_explicitly_allowed() {
        let mut trust = DstackTrust::new(crate::KmsPins {
            ca_spki_der: vec![],
            k256_root: [0; 33],
            mr_kms: None,
        });
        let advisory = "INTEL-SA-00000".to_owned();
        assert!(tcb_posture_allowed(&trust, "UpToDate", &[]));
        assert!(!tcb_posture_allowed(
            &trust,
            "UpToDate",
            std::slice::from_ref(&advisory)
        ));
        trust.allowed_advisory_ids.insert(advisory.clone());
        assert!(tcb_posture_allowed(&trust, "UpToDate", &[advisory]));
        assert!(!tcb_posture_allowed(&trust, "OutOfDate", &[]));
    }
}
