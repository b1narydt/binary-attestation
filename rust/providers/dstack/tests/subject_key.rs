//! `dstack-subject-key-v0` child component and the
//! `dstack-subject-key-brc100-v1` relation on the live frozen-v0 `GetKey`
//! captures.

mod common;

use binary_attestation_core::{
    B64Url, BindingRelationVerifier, Denial, EvidenceVerifier, MAX_COMPONENT_EVIDENCE,
    VerifiedComponent,
};
use binary_attestation_dstack::{
    DSTACK_SUBJECT_KEY_BRC100_RELATION, DSTACK_SUBJECT_KEY_V0_PROVIDER,
    DstackSubjectKeyBrc100Relation, subject_proof_digest,
};
use common::*;
use k256::elliptic_curve::{PrimeField, bigint::ArrayEncoding, bigint::U256, ops::Reduce};
use sha2::{Digest, Sha256};

fn verify_child(probe: &Probe) -> Result<VerifiedComponent, Denial> {
    subject_key_verifier().verify(&child_component(probe), probe.binding, probe.now_ms())
}

fn verify_child_value(
    probe: &Probe,
    value: &serde_json::Value,
) -> Result<VerifiedComponent, Denial> {
    subject_key_verifier().verify(
        &child_component_from_value(value),
        probe.binding,
        probe.now_ms(),
    )
}

fn verified_pair(probe: &Probe) -> (VerifiedComponent, VerifiedComponent) {
    let parent = attest_verifier()
        .verify(&parent_component(probe), probe.binding, probe.now_ms())
        .expect("parent");
    let child = verify_child(probe).expect("child");
    (parent, child)
}

fn relate(
    relation: &DstackSubjectKeyBrc100Relation,
    probe: &Probe,
    parent: &VerifiedComponent,
    child: &VerifiedComponent,
) -> Result<(), Denial> {
    relation.verify(parent, child, &edge(), probe.binding, probe.now_ms())
}

/// secp256k1 group order.
fn curve_order() -> U256 {
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
}

/// Returns the same ECDSA signature with `s` replaced by `n - s` (the
/// malleable high-S twin), as 64 raw bytes.
fn high_s_twin(raw: &[u8]) -> [u8; 64] {
    let s = U256::from_be_slice(&raw[32..64]);
    let high = curve_order().wrapping_sub(&s);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&raw[..32]);
    out[32..].copy_from_slice(&high.to_be_byte_array());
    out
}

fn der_from_raw(raw: &[u8; 64]) -> Vec<u8> {
    let sig = k256::ecdsa::Signature::from_slice(raw).expect("raw signature");
    sig.to_der().as_bytes().to_vec()
}

fn raw_from_der(der: &[u8]) -> [u8; 64] {
    k256::ecdsa::Signature::from_der(der)
        .expect("der")
        .to_bytes()
        .into()
}

#[test]
fn subject_proof_digest_matches_the_recorded_capture_value() {
    for probe in [probe_did(), probe_brc100()] {
        let recorded = String::from_utf8(fixture_bytes(&format!(
            "{}/subject-proof-digest.hex",
            probe.name
        )))
        .expect("hex");
        assert_eq!(
            hex_encode(&subject_proof_digest(&probe.binding)),
            recorded.trim()
        );
    }
}

#[test]
fn live_subject_key_child_verifies_and_is_unbound_on_its_own() {
    for probe in [probe_did(), probe_brc100()] {
        let output = verify_child(&probe).expect("child verifies");
        output.validate().expect("well-formed");
        assert_eq!(output.component_id, CHILD_ID);
        assert_eq!(output.provider, DSTACK_SUBJECT_KEY_V0_PROVIDER);
        // Never a direct BCAP1 binding: composition must route through the
        // verified relation edge.
        assert_eq!(output.binding_digest, B64Url::from_bytes(&[0; 64]));
        let evidence = child_component(&probe)
            .evidence
            .decode_with_limit(MAX_COMPONENT_EVIDENCE)
            .expect("bounded");
        assert_eq!(
            output.evidence_digest,
            B64Url::from_bytes(&Sha256::digest(&evidence))
        );
        assert_eq!(output.measurements["public_key"], probe.identity.public_key);
        assert_eq!(output.measurements["purpose"], "identity");
        assert_eq!(
            output.measurements["kms_link1"],
            hex_encode(&probe.identity.chain[1])
        );
        let app_root = output.measurements["app_root"].as_str().expect("app root");
        assert_eq!(app_root.len(), 66);
        assert!(app_root.starts_with("02") || app_root.starts_with("03"));
        assert_eq!(output.platform["profile"], DSTACK_SUBJECT_KEY_V0_PROVIDER);
        assert_eq!(output.valid_until_ms.get(), u64::MAX);
    }
}

#[test]
fn both_captures_recover_the_same_app_root() {
    let did = verify_child(&probe_did()).expect("did");
    let brc100 = verify_child(&probe_brc100()).expect("brc100");
    assert_eq!(
        did.measurements["app_root"],
        brc100.measurements["app_root"]
    );
    assert_eq!(
        did.measurements["public_key"],
        brc100.measurements["public_key"]
    );
}

#[test]
fn child_bound_to_a_different_binding_digest_is_signature_invalid() {
    let did = probe_did();
    let brc100 = probe_brc100();
    assert_eq!(
        subject_key_verifier()
            .verify(&child_component(&did), brc100.binding, did.now_ms())
            .err(),
        Some(Denial::SignatureInvalid)
    );
}

#[test]
fn tampered_subject_proof_is_signature_invalid() {
    let probe = probe_did();
    let mut identity = probe.identity.clone();
    let mut raw = raw_from_der(&identity.subject_proof_der);
    raw[5] ^= 0x01;
    identity.subject_proof_der = der_from_raw(&raw);
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::SignatureInvalid)
    );
}

#[test]
fn high_s_der_subject_proof_is_signature_invalid() {
    let probe = probe_did();
    let mut identity = probe.identity.clone();
    let raw = raw_from_der(&identity.subject_proof_der);
    let twin = high_s_twin(&raw);
    // The twin is a mathematically valid ECDSA signature for the same key
    // and digest (k256 itself refuses high-S at verification); the verifier
    // must refuse it as non-canonical before any curve arithmetic.
    assert_ne!(twin, raw);
    assert_eq!(
        k256::ecdsa::Signature::from_slice(&twin)
            .expect("twin")
            .normalize_s()
            .map(|normalized| <[u8; 64]>::from(normalized.to_bytes())),
        Some(raw)
    );
    identity.subject_proof_der = der_from_raw(&twin);
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::SignatureInvalid)
    );
}

#[test]
fn non_strict_der_subject_proof_is_signature_invalid() {
    let probe = probe_did();
    let mut identity = probe.identity.clone();
    // BER long-form length for the outer SEQUENCE: 0x30 0x81 len ...
    let body = identity.subject_proof_der[2..].to_vec();
    let mut lax = vec![0x30, 0x81, body.len() as u8];
    lax.extend_from_slice(&body);
    identity.subject_proof_der = lax;
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::SignatureInvalid)
    );
    // Trailing byte after a valid DER signature.
    let mut identity = probe.identity.clone();
    identity.subject_proof_der.push(0);
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::SignatureInvalid)
    );
}

#[test]
fn high_s_chain_link_is_signature_invalid() {
    let probe = probe_did();
    for link in 0..2 {
        let mut identity = probe.identity.clone();
        let twin = high_s_twin(&identity.chain[link][..64]);
        let v = identity.chain[link][64] ^ 0x01;
        identity.chain[link] = twin.to_vec();
        identity.chain[link].push(v);
        assert_eq!(
            verify_child_value(&probe, &child_evidence_value(&identity)).err(),
            Some(Denial::SignatureInvalid),
            "link {link}"
        );
    }
}

#[test]
fn recovery_byte_outside_the_dstack_range_is_signature_invalid() {
    let probe = probe_did();
    assert_eq!(probe.identity.chain[0][64], 1, "captured link 0 uses v=1");
    assert_eq!(probe.identity.chain[1][64], 1, "captured link 1 uses v=1");
    for v in [2u8, 3, 27, 28, 0xff] {
        for link in 0..2 {
            let mut identity = probe.identity.clone();
            identity.chain[link][64] = v;
            assert_eq!(
                verify_child_value(&probe, &child_evidence_value(&identity)).err(),
                Some(Denial::SignatureInvalid),
                "link {link} v={v}"
            );
        }
    }
    // Flipping the parity bit recovers a different key: link 0 then no longer
    // chains to a root the relation accepts (checked in the relation tests),
    // but the child itself still only sees a syntactically valid link.
    let mut identity = probe.identity.clone();
    identity.chain[0][64] = 0;
    let other = verify_child_value(&probe, &child_evidence_value(&identity)).expect("recovers");
    assert_ne!(
        other.measurements["app_root"],
        verify_child(&probe).expect("live").measurements["app_root"]
    );
}

#[test]
fn tampered_link0_bytes_are_signature_invalid_or_change_the_root() {
    let probe = probe_did();
    let mut identity = probe.identity.clone();
    identity.chain[0][0] ^= 0x01;
    // A one-bit change in r either breaks point decompression (refused) or
    // recovers an unrelated key that the relation will refuse. Either way the
    // live app root is never produced.
    match verify_child_value(&probe, &child_evidence_value(&identity)) {
        Err(denial) => assert_eq!(denial, Denial::SignatureInvalid),
        Ok(output) => assert_ne!(
            output.measurements["app_root"],
            verify_child(&probe).expect("live").measurements["app_root"]
        ),
    }
}

#[test]
fn wrong_chain_length_is_malformed() {
    let probe = probe_did();
    let mut value = child_evidence_value(&probe.identity);
    value["signatureChain"] = serde_json::json!([value["signatureChain"][0]]);
    assert_eq!(
        verify_child_value(&probe, &value).err(),
        Some(Denial::Malformed)
    );
    let mut value = child_evidence_value(&probe.identity);
    let link = value["signatureChain"][1].clone();
    value["signatureChain"]
        .as_array_mut()
        .expect("array")
        .push(link);
    assert_eq!(
        verify_child_value(&probe, &value).err(),
        Some(Denial::Malformed)
    );
    let mut value = child_evidence_value(&probe.identity);
    value["signatureChain"][0] = serde_json::json!(B64Url::from_bytes(&[0u8; 64]));
    assert_eq!(
        verify_child_value(&probe, &value).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn non_canonical_jcs_child_evidence_is_malformed() {
    let probe = probe_did();
    let value = child_evidence_value(&probe.identity);
    let pretty = serde_json::to_vec_pretty(&value).expect("pretty");
    assert_eq!(
        subject_key_verifier()
            .verify(
                &child_component_from_bytes(&pretty),
                probe.binding,
                probe.now_ms()
            )
            .err(),
        Some(Denial::Malformed)
    );
    // Same members, non-sorted order, no whitespace.
    let reordered = format!(
        "{{\"signatureChain\":{},\"publicKey\":{},\"signature\":{},\"keyClaim\":{}}}",
        value["signatureChain"], value["publicKey"], value["signature"], value["keyClaim"]
    );
    assert_eq!(
        subject_key_verifier()
            .verify(
                &child_component_from_bytes(reordered.as_bytes()),
                probe.binding,
                probe.now_ms()
            )
            .err(),
        Some(Denial::Malformed)
    );
    // Duplicate member.
    let canonical =
        String::from_utf8(binary_attestation_core::jcs_bytes(&value).expect("jcs")).expect("utf8");
    let duplicated = canonical.replacen("{", "{\"keyClaim\":\"AA\",", 1);
    assert_eq!(
        subject_key_verifier()
            .verify(
                &child_component_from_bytes(duplicated.as_bytes()),
                probe.binding,
                probe.now_ms()
            )
            .err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn unknown_or_missing_child_fields_are_malformed() {
    let probe = probe_did();
    let mut value = child_evidence_value(&probe.identity);
    value["path"] = serde_json::json!("brc100-identity");
    assert_eq!(
        verify_child_value(&probe, &value).err(),
        Some(Denial::Malformed)
    );
    let mut value = child_evidence_value(&probe.identity);
    value.as_object_mut().expect("object").remove("keyClaim");
    assert_eq!(
        verify_child_value(&probe, &value).err(),
        Some(Denial::Malformed)
    );
    assert_eq!(
        subject_key_verifier()
            .verify(
                &child_component_from_bytes(b"[]"),
                probe.binding,
                probe.now_ms()
            )
            .err(),
        Some(Denial::Malformed)
    );
    assert_eq!(
        subject_key_verifier()
            .verify(
                &child_component_from_bytes(b""),
                probe.binding,
                probe.now_ms()
            )
            .err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn key_claim_must_be_the_exact_frozen_v0_link0_preimage() {
    let probe = probe_did();
    let mut value = child_evidence_value(&probe.identity);
    value["keyClaim"] = serde_json::json!(B64Url::from_bytes(
        format!("seal:{}", probe.identity.public_key).as_bytes()
    ));
    assert_eq!(
        verify_child_value(&probe, &value).err(),
        Some(Denial::Malformed)
    );
    let mut value = child_evidence_value(&probe.identity);
    value["keyClaim"] = serde_json::json!(B64Url::from_bytes(
        format!("identity:{}", probe.identity.public_key.to_uppercase()).as_bytes()
    ));
    assert_eq!(
        verify_child_value(&probe, &value).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn public_key_must_be_a_lowercase_compressed_secp256k1_point() {
    let probe = probe_did();
    let mut identity = probe.identity.clone();
    identity.public_key = identity.public_key.to_uppercase();
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::Malformed)
    );
    let mut identity = probe.identity.clone();
    identity.public_key = format!("02{}", "00".repeat(32));
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::Malformed)
    );
    let mut identity = probe.identity.clone();
    identity.public_key = format!("04{}", &identity.public_key[2..]);
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::Malformed)
    );
}

#[test]
fn substituted_public_key_is_signature_invalid() {
    // A different valid key whose proof does not verify.
    let probe = probe_did();
    let mut identity = probe.identity.clone();
    identity.public_key = KMS_K256_ROOT.into();
    assert_eq!(
        verify_child_value(&probe, &child_evidence_value(&identity)).err(),
        Some(Denial::SignatureInvalid)
    );
}

#[test]
fn child_media_type_endorsements_and_size_are_enforced() {
    let probe = probe_did();
    let mut component = child_component(&probe);
    component.media_type = "application/json".into();
    assert_eq!(
        subject_key_verifier()
            .verify(&component, probe.binding, probe.now_ms())
            .err(),
        Some(Denial::Malformed)
    );
    let mut component = child_component(&probe);
    component.endorsements = Some(B64Url::from_bytes(b"x"));
    assert_eq!(
        subject_key_verifier()
            .verify(&component, probe.binding, probe.now_ms())
            .err(),
        Some(Denial::Malformed)
    );
    let mut component = child_component(&probe);
    component.provider = "dstack-subject-key-v1".into();
    assert_eq!(
        subject_key_verifier()
            .verify(&component, probe.binding, probe.now_ms())
            .err(),
        Some(Denial::Malformed)
    );
    let oversized = child_component_from_bytes(&vec![b' '; 8 * 1024]);
    assert_eq!(
        subject_key_verifier()
            .verify(&oversized, probe.binding, probe.now_ms())
            .err(),
        Some(Denial::ResourceLimit)
    );
}

#[test]
fn live_relation_chains_link1_to_the_pinned_kms_root() {
    for probe in [probe_did(), probe_brc100()] {
        let (parent, child) = verified_pair(&probe);
        relate(&relation(), &probe, &parent, &child).expect("relation verifies");
    }
}

#[test]
fn wrong_k256_root_pin_is_root_untrusted() {
    let probe = probe_did();
    let (parent, child) = verified_pair(&probe);
    let mut pins = kms_pins();
    pins.k256_root = hex_decode(&probe.identity.public_key)
        .try_into()
        .expect("33");
    let relation = DstackSubjectKeyBrc100Relation::new(pins).expect("relation");
    assert_eq!(
        relate(&relation, &probe, &parent, &child),
        Err(Denial::RootUntrusted)
    );
}

#[test]
fn app_id_mismatch_breaks_link1_recovery_to_the_pinned_root() {
    let probe = probe_did();
    let (mut parent, child) = verified_pair(&probe);
    parent.measurements.insert(
        "app_id".into(),
        serde_json::json!(format!("{}ff", &APP_ID[..38])),
    );
    assert_eq!(
        relate(&relation(), &probe, &parent, &child),
        Err(Denial::RootUntrusted)
    );
    parent.measurements.remove("app_id");
    assert_eq!(
        relate(&relation(), &probe, &parent, &child),
        Err(Denial::Malformed)
    );
}

#[test]
fn parent_key_provider_mismatch_is_root_untrusted() {
    let probe = probe_did();
    let (mut parent, child) = verified_pair(&probe);
    let spki = hex_encode(&kms_pins().ca_spki_der);
    parent.measurements.insert(
        "key_provider_id".into(),
        serde_json::json!(format!("{}00", &spki[..spki.len() - 2])),
    );
    assert_eq!(
        relate(&relation(), &probe, &parent, &child),
        Err(Denial::RootUntrusted)
    );
}

#[test]
fn link1_substituted_by_another_valid_signature_is_root_untrusted() {
    let probe = probe_did();
    let (parent, mut child) = verified_pair(&probe);
    child.measurements.insert(
        "kms_link1".into(),
        serde_json::json!(hex_encode(&probe.identity.chain[0])),
    );
    assert_eq!(
        relate(&relation(), &probe, &parent, &child),
        Err(Denial::RootUntrusted)
    );
}

#[test]
fn flipped_link0_parity_recovers_a_root_the_relation_refuses() {
    let probe = probe_did();
    let (parent, _) = verified_pair(&probe);
    let mut identity = probe.identity.clone();
    identity.chain[0][64] = 0;
    let child = verify_child_value(&probe, &child_evidence_value(&identity)).expect("child");
    assert_eq!(
        relate(&relation(), &probe, &parent, &child),
        Err(Denial::RootUntrusted)
    );
}

#[test]
fn provider_substitution_is_unsupported_provider() {
    let probe = probe_did();
    let (parent, child) = verified_pair(&probe);
    let mut mock_parent = parent.clone();
    mock_parent.provider = "mock-dstack".into();
    assert_eq!(
        relate(&relation(), &probe, &mock_parent, &child),
        Err(Denial::UnsupportedProvider)
    );
    let mut other_parent = parent.clone();
    other_parent.provider = "dstack-v1".into();
    assert_eq!(
        relate(&relation(), &probe, &other_parent, &child),
        Err(Denial::UnsupportedProvider)
    );
    // Roles swapped on a consistently swapped edge: the plugin kinds are
    // wrong even though the edge is well-formed.
    let mut swapped = edge();
    swapped.parent_component_id = CHILD_ID.into();
    swapped.child_component_id = PARENT_ID.into();
    assert_eq!(
        relation().verify(&child, &parent, &swapped, probe.binding, probe.now_ms()),
        Err(Denial::UnsupportedProvider)
    );
}

#[test]
fn parent_without_a_direct_binding_is_binding_mismatch() {
    let probe = probe_did();
    let (mut parent, child) = verified_pair(&probe);
    parent.binding_digest = B64Url::from_bytes(&probe_brc100().binding);
    assert_eq!(
        relate(&relation(), &probe, &parent, &child),
        Err(Denial::BindingMismatch)
    );
}

#[test]
fn edge_shape_is_enforced() {
    let probe = probe_did();
    let (parent, child) = verified_pair(&probe);
    let mut with_evidence = edge();
    with_evidence.evidence = Some(B64Url::from_bytes(b"x"));
    assert_eq!(
        relation().verify(
            &parent,
            &child,
            &with_evidence,
            probe.binding,
            probe.now_ms()
        ),
        Err(Denial::Malformed)
    );
    let mut renamed = edge();
    renamed.relation = "dstack-tdx-rtmr3-nvidia-boottime-v1".into();
    assert_eq!(
        relation().verify(&parent, &child, &renamed, probe.binding, probe.now_ms()),
        Err(Denial::Malformed)
    );
    let mut swapped = edge();
    swapped.parent_component_id = CHILD_ID.into();
    swapped.child_component_id = PARENT_ID.into();
    assert_eq!(
        relation().verify(&parent, &child, &swapped, probe.binding, probe.now_ms()),
        Err(Denial::Malformed)
    );
}

#[test]
fn relation_registry_accepts_the_production_relation_name() {
    let registry = binary_attestation_core::RelationRegistry::new();
    registry
        .register(std::sync::Arc::new(relation()))
        .expect("registers");
    assert!(registry.get(DSTACK_SUBJECT_KEY_BRC100_RELATION).is_ok());
    assert!(matches!(
        DstackSubjectKeyBrc100Relation::new(binary_attestation_dstack::KmsPins {
            ca_spki_der: vec![],
            k256_root: kms_pins().k256_root,
            mr_kms: None,
        }),
        Err(Denial::VerifierUnavailable)
    ));
}

#[test]
fn kms_ca_spki_pin_matches_the_quote_authenticated_key_provider_event() {
    // The pin comes from the KMS GetMeta certificate; the event id must equal
    // it byte for byte, otherwise the live positive tests could not pass.
    let info: serde_json::Value =
        serde_json::from_slice(&fixture_bytes("info.json")).expect("info.json");
    let key_provider: serde_json::Value =
        serde_json::from_str(info["key_provider_info"].as_str().expect("string")).expect("json");
    assert_eq!(key_provider["name"], "kms");
    assert_eq!(key_provider["id"], hex_encode(&kms_pins().ca_spki_der));
}

#[test]
fn curve_helpers_are_sound() {
    // Sanity for the test's own high-S construction.
    let s = k256::Scalar::from_repr(k256::FieldBytes::from([1u8; 32])).expect("scalar");
    let order_minus = curve_order().wrapping_sub(&U256::from_be_slice(&s.to_bytes()));
    let reduced = <k256::Scalar as Reduce<U256>>::reduce(order_minus);
    assert_eq!(reduced, -s);
}
