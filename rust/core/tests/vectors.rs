use binary_attestation_core::{
    AttestationSubject, B64Url, Challenge, Denial, EvidenceBindingEdge, EvidenceBundle,
    EvidenceComponent, SignedSecuritySnapshot, TransportMessage, binding_digest, jcs_bytes,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hex_decode(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex utf8"), 16).expect("hex")
        })
        .collect()
}

fn set_path(value: &mut Value, path: &str, replacement: Value) {
    let mut parts = path.split('.').peekable();
    let mut current = value;
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            current
                .as_object_mut()
                .expect("object")
                .insert(part.to_owned(), replacement);
            return;
        }
        current = current
            .as_object_mut()
            .expect("object")
            .get_mut(part)
            .expect("path");
    }
}

#[test]
fn transcript_kats_and_mutations_are_exact() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../vectors/bcap1-transcript.json"))
            .expect("vectors");
    let valid = vectors["valid"].as_array().expect("valid");
    for vector in valid {
        let challenge: Challenge =
            serde_json::from_value(vector["input"].clone()).expect("challenge");
        let preimage = binary_attestation_core::TranscriptPreimage::for_challenge(&challenge)
            .expect("preimage");
        assert_eq!(
            preimage.as_bytes(),
            hex_decode(vector["preimageHex"].as_str().expect("hex")),
            "{}",
            vector["id"]
        );
        assert_eq!(
            binding_digest(&challenge).expect("digest").as_slice(),
            hex_decode(vector["bindingDigestHex"].as_str().expect("hex")),
            "{}",
            vector["id"]
        );
    }
    for vector in vectors["mutations"].as_array().expect("mutations") {
        let base = valid
            .iter()
            .find(|candidate| candidate["id"] == vector["base"])
            .expect("base");
        let mut input = base["input"].clone();
        set_path(
            &mut input,
            vector["path"].as_str().expect("path"),
            vector["value"].clone(),
        );
        let challenge: Challenge = serde_json::from_value(input).expect("mutated challenge");
        let preimage = binary_attestation_core::TranscriptPreimage::for_challenge(&challenge)
            .expect("preimage");
        assert_eq!(
            preimage.as_bytes(),
            hex_decode(vector["preimageHex"].as_str().expect("hex")),
            "{}",
            vector["id"]
        );
        assert_eq!(
            binding_digest(&challenge).expect("digest").as_slice(),
            hex_decode(vector["bindingDigestHex"].as_str().expect("hex")),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn transcript_rejection_kats_fail_closed() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../vectors/bcap1-transcript.json"))
            .expect("vectors");
    for rejection in vectors["rejections"].as_array().expect("rejections") {
        let base = if rejection["id"]
            .as_str()
            .is_some_and(|id| id.contains("brc100"))
        {
            vectors["valid"][1]["input"].clone()
        } else {
            vectors["valid"][0]["input"].clone()
        };
        let mut input = base;
        set_path(
            &mut input,
            rejection["field"].as_str().expect("field"),
            rejection["value"].clone(),
        );
        let accepted = serde_json::from_value::<Challenge>(input)
            .is_ok_and(|challenge| challenge.validate().is_ok());
        assert!(!accepted, "{}", rejection["id"]);
    }
}

#[test]
fn security_snapshot_jcs_kat_is_exact() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../vectors/bcap1-security-snapshot-jcs.json"
    ))
    .expect("vectors");
    for vector in vectors["valid"].as_array().expect("valid") {
        let body = vector["body"].clone();
        assert_eq!(
            jcs_bytes(&body).expect("jcs"),
            vector["bodyJcsUtf8"].as_str().expect("jcs").as_bytes()
        );
        assert_eq!(
            Sha256::digest(jcs_bytes(&body).expect("jcs")).as_ref(),
            hex_decode(vector["trustDigestHex"].as_str().expect("digest")),
            "{}",
            vector["id"]
        );
        let signed: SignedSecuritySnapshot =
            serde_json::from_value(vector["signedSnapshot"].clone()).expect("snapshot");
        signed.validate().expect("valid snapshot");
    }
}

#[test]
fn transport_kats_decode_only_with_authenticated_identities_and_digest() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../vectors/bcap1-transport.json"))
            .expect("vectors");
    for vector in vectors["valid"].as_array().expect("valid") {
        let message: TransportMessage =
            serde_json::from_value(vector["message"].clone()).expect("message");
        let peer: AttestationSubject =
            serde_json::from_value(vector["authenticatedPeer"].clone()).expect("peer");
        let local: AttestationSubject =
            serde_json::from_value(vector["authenticatedLocalSubject"].clone()).expect("local");
        assert!(message.decode(peer, &local).is_ok(), "{}", vector["id"]);
        assert_eq!(
            message
                .payload
                .decode_with_limit(binary_attestation_core::MAX_BUNDLE_BYTES)
                .expect("bounded payload"),
            vector["payloadJcsUtf8"]
                .as_str()
                .expect("payload")
                .as_bytes()
        );
        assert_eq!(
            Sha256::digest(
                message
                    .payload
                    .decode_with_limit(binary_attestation_core::MAX_BUNDLE_BYTES)
                    .expect("bounded payload"),
            )
            .as_ref(),
            hex_decode(vector["payloadDigestHex"].as_str().expect("digest"))
        );
    }
}

#[test]
fn core_rejection_vectors_refuse_duplicate_edges_and_invalid_unicode() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../vectors/bcap1-core-rejections.json"))
            .expect("vectors");
    assert_eq!(vectors["format"].as_str(), Some("bcap1-core-rejections-v1"));
    for unicode in vectors["unicode"].as_array().expect("unicode") {
        assert!(
            serde_json::from_str::<String>(unicode["valueJson"].as_str().expect("valueJson"))
                .is_err(),
            "{}",
            unicode["id"]
        );
    }
    for rejection in vectors["bundleRejections"]
        .as_array()
        .expect("bundleRejections")
    {
        let components = rejection["componentIds"]
            .as_array()
            .expect("component ids")
            .iter()
            .map(|id| EvidenceComponent {
                component_id: id.as_str().expect("component id").to_owned(),
                provider: "fixture-v1".into(),
                media_type: "application/fixture".into(),
                evidence: B64Url::from_bytes(&[1]),
                endorsements: None,
                untrusted_metadata: None,
            })
            .collect();
        let edges = rejection["edges"]
            .as_array()
            .expect("edges")
            .iter()
            .map(|edge| EvidenceBindingEdge {
                parent_component_id: edge["parentComponentId"]
                    .as_str()
                    .expect("parent")
                    .to_owned(),
                child_component_id: edge["childComponentId"].as_str().expect("child").to_owned(),
                relation: edge["relation"].as_str().expect("relation").to_owned(),
                evidence: None,
            });
        let bundle = EvidenceBundle {
            protocol_version: 1,
            challenge_id: B64Url::from_bytes(&[0; 16]),
            subject: AttestationSubject {
                kind: "did".into(),
                value: "peer".into(),
            },
            components,
            binding_edges: Some(edges.collect()),
        };
        assert_eq!(
            bundle.validate(),
            Err(Denial::Malformed),
            "{}",
            rejection["id"]
        );
    }
}
