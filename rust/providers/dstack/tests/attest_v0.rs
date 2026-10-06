//! `dstack-attest-v0` provider: positive path on the live dstack 0.5.9
//! production captures and fail-closed negatives derived from them.

mod common;

use std::collections::BTreeSet;

use binary_attestation_core::{B64Url, Denial, EvidenceVerifier, VerifiedComponent};
use binary_attestation_dstack::{
    DSTACK_ATTEST_V0_PROVIDER, DstackAttestV0Verifier, DstackTrust, PinnedCollateral,
    events::{LAUNCH_EVENT_ORDER, replay_rtmr3, runtime_event_digest},
    scale::{LegacyAttestationV0, RuntimeEvent, TdxEvent},
};
use common::*;
use sha2::{Digest, Sha256};

/// TDX v4 quote: 48-byte header, then the TD report; `report_data` starts at
/// report offset 520 and `mr_td` at 136.
const QUOTE_REPORT_DATA_OFFSET: usize = 48 + 520;
const QUOTE_MR_TD_OFFSET: usize = 48 + 136;

fn info_tcb() -> serde_json::Value {
    let info: serde_json::Value =
        serde_json::from_slice(&fixture_bytes("info.json")).expect("info.json");
    match &info["tcb_info"] {
        serde_json::Value::String(text) => serde_json::from_str(text).expect("tcb_info json"),
        other => other.clone(),
    }
}

fn verify(verifier: &DstackAttestV0Verifier, probe: &Probe) -> Result<VerifiedComponent, Denial> {
    verifier.verify(&parent_component(probe), probe.binding, probe.now_ms())
}

fn verify_envelope(probe: &Probe, envelope: &[u8]) -> Result<VerifiedComponent, Denial> {
    attest_verifier().verify(
        &parent_component_from(envelope),
        probe.binding,
        probe.now_ms(),
    )
}

fn decoded(probe: &Probe) -> LegacyAttestationV0 {
    LegacyAttestationV0::decode(&probe.envelope).expect("live envelope decodes")
}

fn measurement(output: &VerifiedComponent, key: &str) -> String {
    output.measurements[key]
        .as_str()
        .unwrap_or_else(|| panic!("measurement {key} is a string"))
        .to_owned()
}

/// Applies `edit` to the RTMR3 runtime events in BOTH lists the envelope
/// carries, so the lists still agree and the test isolates the replay/order
/// check rather than the list-agreement check.
fn edit_launch_events(
    envelope: &mut LegacyAttestationV0,
    edit: impl Fn(&mut Vec<(String, Vec<u8>)>),
) {
    let mut events = envelope
        .runtime_events
        .iter()
        .map(|event| (event.event.clone(), event.payload.clone()))
        .collect::<Vec<_>>();
    edit(&mut events);
    envelope.runtime_events = events
        .iter()
        .map(|(event, payload)| RuntimeEvent {
            event: event.clone(),
            payload: payload.clone(),
        })
        .collect();
    let template = envelope
        .tdx_events
        .iter()
        .find(|event| event.imr == 3)
        .expect("an RTMR3 event")
        .clone();
    envelope.tdx_events.retain(|event| event.imr != 3);
    envelope
        .tdx_events
        .extend(events.iter().map(|(event, payload)| TdxEvent {
            imr: 3,
            event_type: template.event_type,
            digest: vec![],
            event: event.clone(),
            event_payload: payload.clone(),
        }));
}

#[test]
fn live_did_probe_envelope_verifies_with_pinned_trust() {
    let probe = probe_did();
    let output = verify(&attest_verifier(), &probe).expect("live evidence verifies");
    output.validate().expect("well-formed verified component");
    assert_eq!(output.component_id, PARENT_ID);
    assert_eq!(output.provider, DSTACK_ATTEST_V0_PROVIDER);
    assert_eq!(output.binding_digest, B64Url::from_bytes(&probe.binding));
    assert_eq!(
        output.evidence_digest,
        B64Url::from_bytes(&Sha256::digest(&probe.envelope))
    );

    let tcb = info_tcb();
    for register in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
        assert_eq!(
            measurement(&output, register),
            tcb[register].as_str().expect("register"),
            "{register} must equal the guest's own /Info view of the quote"
        );
    }
    assert_eq!(measurement(&output, "compose_hash"), COMPOSE_HASH);
    assert_eq!(
        measurement(&output, "mr_config_id"),
        format!("01{COMPOSE_HASH}{}", "00".repeat(15))
    );
    assert_eq!(measurement(&output, "app_id"), APP_ID);
    assert_eq!(measurement(&output, "instance_id"), INSTANCE_ID);
    assert_eq!(measurement(&output, "os_image_hash"), PROD_OS_IMAGE_HASH);
    assert_eq!(measurement(&output, "mr_kms"), MR_KMS);
    assert_eq!(
        measurement(&output, "key_provider_id"),
        hex_encode(&kms_pins().ca_spki_der)
    );
    assert_eq!(measurement(&output, "storage_fs"), hex_encode(b"zfs"));
    assert_eq!(measurement(&output, "vm_config_sha256").len(), 64);

    assert_eq!(output.platform["tee"], "tdx");
    assert_eq!(output.platform["profile"], DSTACK_ATTEST_V0_PROVIDER);
    assert_eq!(output.platform["fmspc"], FMSPC);
    assert_eq!(output.platform["quote_version"], 4);
    assert_eq!(output.platform["key_provider_name"], "kms");
    assert_eq!(output.platform["td_debug"], false);
    assert_eq!(output.tcb["status"], "UpToDate");
    assert!(output.advisories.is_empty());
    assert_eq!(output.valid_until_ms.get(), COLLATERAL_EARLIEST_EXPIRY_MS);
}

#[test]
fn live_brc100_probe_envelope_verifies_with_pinned_trust() {
    let probe = probe_brc100();
    let output = verify(&attest_verifier(), &probe).expect("live evidence verifies");
    assert_eq!(output.binding_digest, B64Url::from_bytes(&probe.binding));
    assert_eq!(measurement(&output, "app_id"), APP_ID);
    assert_eq!(output.tcb["status"], "UpToDate");
}

#[test]
fn scale_decode_encode_round_trip_is_byte_exact() {
    for probe in [probe_did(), probe_brc100()] {
        let envelope = decoded(&probe);
        assert_eq!(envelope.encode(), probe.envelope);
        assert_eq!(envelope.report_data, probe.binding);
        assert_eq!(envelope.runtime_events.len(), LAUNCH_EVENT_ORDER.len());
        assert_eq!(
            envelope
                .tdx_events
                .iter()
                .filter(|event| event.imr == 3)
                .count(),
            LAUNCH_EVENT_ORDER.len()
        );
        assert_eq!(envelope.tdx_events.len(), 30);
        assert!(envelope.config.starts_with("{\"os_image_hash\":"));
    }
}

#[test]
fn rtmr3_replay_from_recomputed_digests_matches_the_quote_register() {
    let probe = probe_did();
    let envelope = decoded(&probe);
    let replayed = replay_rtmr3(
        envelope
            .runtime_events
            .iter()
            .map(|event| runtime_event_digest(&event.event, &event.payload)),
    );
    assert_eq!(
        hex_encode(&replayed),
        info_tcb()["rtmr3"].as_str().expect("rtmr3")
    );
}

#[test]
fn supplied_event_digest_fields_are_never_trusted() {
    let probe = probe_did();
    // Zeroing the carried digests must not change the verdict: the verifier
    // recomputes every digest and replays RTMR3 from zero.
    let mut envelope = decoded(&probe);
    for event in &mut envelope.tdx_events {
        event.digest = vec![0; event.digest.len()];
    }
    verify_envelope(&probe, &envelope.encode()).expect("supplied digests are ignored");
    // ...and a *plausible* digest cannot vouch for a tampered payload either.
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| {
        events[2].1[0] ^= 0x01; // compose-hash payload
    });
    for event in envelope
        .tdx_events
        .iter_mut()
        .filter(|event| event.imr == 3)
    {
        event.digest = runtime_event_digest(&event.event, &event.event_payload).to_vec();
    }
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::MeasurementMismatch)
    );
}

#[test]
fn one_byte_quote_tamper_in_report_data_is_signature_invalid() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    flip_bit(&mut envelope.quote, QUOTE_REPORT_DATA_OFFSET);
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::SignatureInvalid)
    );
}

#[test]
fn one_byte_quote_tamper_in_mrtd_is_signature_invalid() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    flip_bit(&mut envelope.quote, QUOTE_MR_TD_OFFSET);
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::SignatureInvalid)
    );
}

#[test]
fn quote_embedded_pck_leaf_must_be_the_pinned_one() {
    // The quote's embedded PCK chain is unsigned and only selects collateral;
    // the verified chain is the pinned one. A quote whose embedded leaf is not
    // the pinned leaf has no pinned collateral and is refused before DCAP.
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    let marker = b"-----BEGIN CERTIFICATE-----";
    let start = envelope
        .quote
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("PEM PCK chain inside the quote");
    // A different valid base64 character inside the leaf's serial number.
    let index = start + marker.len() + 40;
    envelope.quote[index] = if envelope.quote[index] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::EndorsementsMissing)
    );
    // Corrupting the PEM framing makes the quote unparseable for selection.
    let mut envelope = decoded(&probe);
    envelope.quote[start + 2] = b'X';
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn one_byte_envelope_report_data_tamper_is_binding_mismatch() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    flip_bit(&mut envelope.report_data, 63);
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::BindingMismatch)
    );
}

#[test]
fn one_byte_runtime_event_payload_tamper_is_measurement_mismatch() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| {
        events[6].1[31] ^= 0x01; // os-image-hash payload
    });
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::MeasurementMismatch)
    );
}

#[test]
fn disagreeing_tdx_and_runtime_event_lists_are_malformed() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    envelope.runtime_events[1].payload[0] ^= 0x01;
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::Malformed)
    );
    let mut envelope = decoded(&probe);
    envelope.runtime_events.pop();
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn one_byte_config_os_image_hash_tamper_is_measurement_mismatch() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    envelope.config = envelope
        .config
        .replacen(&PROD_OS_IMAGE_HASH[..8], "deadbeef", 1);
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::MeasurementMismatch)
    );
    let mut envelope = decoded(&probe);
    envelope.config = "not json".into();
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn unmeasured_config_tamper_changes_the_exposed_config_digest() {
    // vm_config is carried, not measured, on 0.5.x. The provider exposes its
    // digest so a policy can pin it; see the policy tests for the refusal.
    let probe = probe_did();
    let baseline = verify(&attest_verifier(), &probe).expect("live");
    let mut envelope = decoded(&probe);
    envelope.config = envelope
        .config
        .replacen("\"cpu_count\":1", "\"cpu_count\":2", 1);
    assert_ne!(envelope.config, decoded(&probe).config);
    let tampered = verify_envelope(&probe, &envelope.encode()).expect("config is not measured");
    assert_ne!(
        measurement(&baseline, "vm_config_sha256"),
        measurement(&tampered, "vm_config_sha256")
    );
}

#[test]
fn reordered_launch_events_are_measurement_mismatch() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| events.swap(1, 2));
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::MeasurementMismatch)
    );
}

#[test]
fn missing_launch_event_is_measurement_mismatch() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| {
        events.remove(8); // storage-fs
    });
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::MeasurementMismatch)
    );
}

#[test]
fn duplicated_launch_event_is_measurement_mismatch() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| {
        let last = events.last().cloned().expect("system-ready");
        events.push(last);
    });
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::MeasurementMismatch)
    );
}

#[test]
fn extra_launch_event_is_measurement_mismatch() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| {
        events.insert(9, ("custom-event".into(), b"x".to_vec()));
    });
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::MeasurementMismatch)
    );
}

#[test]
fn malformed_launch_payload_lengths_are_malformed() {
    let probe = probe_did();
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| events[1].1.push(0)); // app-id 21 bytes
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::Malformed)
    );
    let mut envelope = decoded(&probe);
    edit_launch_events(&mut envelope, |events| {
        events[7].1 = br#"{"name":"kms","id":"3059","extra":1}"#.to_vec();
    });
    assert_eq!(
        verify_envelope(&probe, &envelope.encode()).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn wrong_expected_binding_is_binding_mismatch() {
    let did = probe_did();
    let brc100 = probe_brc100();
    assert_eq!(
        attest_verifier()
            .verify(&parent_component(&did), brc100.binding, did.now_ms())
            .err(),
        Some(Denial::BindingMismatch)
    );
}

#[test]
fn quote_and_envelope_report_data_disagreement_is_binding_mismatch() {
    // Both captures are genuine quotes from the same CVM. Splicing the
    // brc100 quote under the did envelope keeps the envelope field equal to the
    // expected binding, so only the DCAP-authenticated field can refuse it.
    let did = probe_did();
    let mut spliced = decoded(&did);
    spliced.quote = decoded(&probe_brc100()).quote;
    assert_eq!(
        verify_envelope(&did, &spliced.encode()).err(),
        Some(Denial::BindingMismatch)
    );
}

#[test]
fn unknown_attestation_quote_variant_is_unsupported_provider() {
    let probe = probe_did();
    for variant in [1u8, 2, 3, 4, 5] {
        let mut envelope = probe.envelope.clone();
        envelope[1] = variant;
        assert_eq!(
            verify_envelope(&probe, &envelope).err(),
            Some(Denial::UnsupportedProvider),
            "AttestationQuote variant {variant}"
        );
    }
}

#[test]
fn unknown_envelope_version_is_unsupported_version() {
    let probe = probe_did();
    let mut envelope = probe.envelope.clone();
    envelope[0] = 1;
    assert_eq!(
        verify_envelope(&probe, &envelope).err(),
        Some(Denial::UnsupportedVersion)
    );
}

#[test]
fn trailing_bytes_are_malformed() {
    let probe = probe_did();
    let mut envelope = probe.envelope.clone();
    envelope.push(0);
    assert_eq!(
        verify_envelope(&probe, &envelope).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn truncated_envelope_is_malformed() {
    let probe = probe_did();
    for cut in [1usize, 2, 3, 100, 5_000, probe.envelope.len() - 1] {
        assert_eq!(
            verify_envelope(&probe, &probe.envelope[..cut]).err(),
            Some(Denial::Malformed),
            "cut at {cut}"
        );
    }
    assert_eq!(verify_envelope(&probe, &[]).err(), Some(Denial::Malformed));
}

#[test]
fn oversized_compact_lengths_are_resource_limit_before_allocation() {
    let probe = probe_did();
    // Quote length claiming 10 MiB in four-byte compact mode.
    let ten_mib = 10u32 * 1024 * 1024;
    let mut envelope = vec![0u8, 0u8];
    envelope.extend_from_slice(&((ten_mib << 2) | 0b10).to_le_bytes());
    assert_eq!(
        verify_envelope(&probe, &envelope).err(),
        Some(Denial::ResourceLimit)
    );
    // Big-integer compact mode (0b11) is never needed for a bounded envelope.
    let big_int = [0u8, 0u8, 0b11, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        verify_envelope(&probe, &big_int).err(),
        Some(Denial::ResourceLimit)
    );
    // Event count claiming 2^20 events after the genuine (minimally encoded)
    // quote prefix: version, variant, two-byte compact length, quote bytes.
    let quote_len = decoded(&probe).quote.len();
    let mut envelope = probe.envelope[..4 + quote_len].to_vec();
    envelope.extend_from_slice(&((1u32 << 20 << 2) | 0b10).to_le_bytes());
    assert_eq!(
        verify_envelope(&probe, &envelope).err(),
        Some(Denial::ResourceLimit)
    );
}

#[test]
fn non_minimal_compact_encoding_is_malformed() {
    let probe = probe_did();
    let decoded = decoded(&probe);
    // The quote length (5010) fits two-byte mode; four-byte mode is non-minimal.
    let mut envelope = vec![0u8, 0u8];
    envelope.extend_from_slice(&(((decoded.quote.len() as u32) << 2) | 0b10).to_le_bytes());
    envelope.extend_from_slice(&probe.envelope[4..]);
    assert_eq!(
        verify_envelope(&probe, &envelope).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn dev_os_image_hash_is_refused() {
    let probe = probe_did();
    let mut trust = trust();
    trust.allowed_os_image_hashes =
        BTreeSet::from([hex_decode(DEV_OS_IMAGE_HASH).try_into().expect("32")]);
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    assert_eq!(
        verify(&verifier, &probe).err(),
        Some(Denial::MeasurementMismatch)
    );
}

#[test]
fn disallowed_tcb_status_is_tcb_disallowed() {
    let probe = probe_did();
    let mut trust = trust();
    trust.allowed_tcb_statuses = BTreeSet::from(["SWHardeningNeeded".to_owned()]);
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    assert_eq!(verify(&verifier, &probe).err(), Some(Denial::TcbDisallowed));
}

#[test]
fn collateral_missing_for_the_quote_fmspc_is_endorsements_missing() {
    let probe = probe_did();
    let other_platform = String::from_utf8(fixture_bytes("collateral.json"))
        .expect("utf8")
        .replace(FMSPC, "00A06F000000");
    let mut trust = trust();
    trust.collateral = vec![PinnedCollateral::from_json(other_platform.as_bytes()).expect("pin")];
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    assert_eq!(
        verify(&verifier, &probe).err(),
        Some(Denial::EndorsementsMissing)
    );
}

#[test]
fn stale_collateral_is_endorsements_stale() {
    let probe = probe_did();
    let verifier = attest_verifier();
    assert_eq!(
        verifier
            .verify(
                &parent_component(&probe),
                probe.binding,
                COLLATERAL_EARLIEST_EXPIRY_MS + 1
            )
            .err(),
        Some(Denial::EndorsementsStale)
    );
    // ...and collateral issued after the trusted clock is not yet valid.
    assert_eq!(
        verifier
            .verify(&parent_component(&probe), probe.binding, 1_000)
            .err(),
        Some(Denial::EndorsementsStale)
    );
}

#[test]
fn wrong_kms_ca_spki_pin_is_root_untrusted() {
    let probe = probe_did();
    let mut trust = trust();
    let last = trust.kms.ca_spki_der.len() - 1;
    trust.kms.ca_spki_der[last] ^= 0x01;
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    assert_eq!(verify(&verifier, &probe).err(), Some(Denial::RootUntrusted));
}

#[test]
fn wrong_mr_kms_pin_is_root_untrusted() {
    let probe = probe_did();
    let mut trust = trust();
    trust.kms.mr_kms = Some([0x42; 32]);
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    assert_eq!(verify(&verifier, &probe).err(), Some(Denial::RootUntrusted));
    let mut trust = common::trust();
    trust.kms.mr_kms = None;
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    verify(&verifier, &probe).expect("mr-kms pin is optional");
}

#[test]
fn compose_hash_and_app_id_allowlists_are_enforced() {
    let probe = probe_did();
    let mut trust = trust();
    trust.allowed_compose_hashes = BTreeSet::from([[0x11; 32]]);
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    assert_eq!(
        verify(&verifier, &probe).err(),
        Some(Denial::MeasurementMismatch)
    );

    let mut trust = common::trust();
    trust.allowed_app_ids = Some(BTreeSet::from([[0x22; 20]]));
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    assert_eq!(
        verify(&verifier, &probe).err(),
        Some(Denial::MeasurementMismatch)
    );

    let mut trust = common::trust();
    trust.allowed_compose_hashes =
        BTreeSet::from([hex_decode(COMPOSE_HASH).try_into().expect("32")]);
    trust.allowed_app_ids = Some(BTreeSet::from([hex_decode(APP_ID).try_into().expect("20")]));
    let verifier = DstackAttestV0Verifier::new(trust).expect("verifier");
    verify(&verifier, &probe).expect("matching allowlists");
}

#[test]
fn verifier_construction_refuses_incomplete_trust() {
    let mut trust = trust();
    trust.collateral.clear();
    assert!(matches!(
        DstackAttestV0Verifier::new(trust),
        Err(Denial::VerifierUnavailable)
    ));
    let mut trust = common::trust();
    trust.allowed_os_image_hashes.clear();
    assert!(matches!(
        DstackAttestV0Verifier::new(trust),
        Err(Denial::VerifierUnavailable)
    ));
    let mut trust = common::trust();
    trust.allowed_tcb_statuses.clear();
    assert!(matches!(
        DstackAttestV0Verifier::new(trust),
        Err(Denial::VerifierUnavailable)
    ));
    let mut trust = common::trust();
    trust.allowed_compose_hashes.clear();
    assert!(matches!(
        DstackAttestV0Verifier::new(trust),
        Err(Denial::VerifierUnavailable)
    ));
    let mut trust = common::trust();
    trust.kms.k256_root = [0; 33];
    assert!(matches!(
        DstackAttestV0Verifier::new(trust),
        Err(Denial::VerifierUnavailable)
    ));
    let mut trust = common::trust();
    trust.kms.ca_spki_der.clear();
    assert!(matches!(
        DstackAttestV0Verifier::new(trust),
        Err(Denial::VerifierUnavailable)
    ));
    assert!(matches!(DstackTrust::new(kms_pins()).collateral.len(), 0));
}

#[test]
fn wrong_media_type_or_provider_name_is_malformed() {
    let probe = probe_did();
    let mut component = parent_component(&probe);
    component.media_type = "application/octet-stream".into();
    assert_eq!(
        attest_verifier()
            .verify(&component, probe.binding, probe.now_ms())
            .err(),
        Some(Denial::Malformed)
    );
    let mut component = parent_component(&probe);
    component.provider = "dstack-v1".into();
    assert_eq!(
        attest_verifier()
            .verify(&component, probe.binding, probe.now_ms())
            .err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn unexpected_endorsements_are_malformed() {
    let probe = probe_did();
    let mut component = parent_component(&probe);
    component.endorsements = Some(B64Url::from_bytes(b"{}"));
    assert_eq!(
        attest_verifier()
            .verify(&component, probe.binding, probe.now_ms())
            .err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn registry_accepts_the_production_provider_name() {
    let registry = binary_attestation_core::ProviderRegistry::new();
    registry
        .register(std::sync::Arc::new(attest_verifier()))
        .expect("dstack-attest-v0 is not a mock name");
    assert!(registry.get(DSTACK_ATTEST_V0_PROVIDER).is_ok());
}
