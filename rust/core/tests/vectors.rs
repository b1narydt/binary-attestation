use std::collections::BTreeMap;

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
        let decoded = match message.message_type {
            binary_attestation_core::MessageType::Challenge => {
                message.decode_challenge(peer.clone(), &local)
            }
            binary_attestation_core::MessageType::Evidence => {
                message.decode_evidence(peer.clone(), &local, &message.context_digest)
            }
        };
        assert!(decoded.is_ok(), "{}", vector["id"]);
        if message.message_type == binary_attestation_core::MessageType::Evidence {
            assert!(
                matches!(
                    message.decode_evidence(peer, &local, &B64Url::from_bytes(&[1; 32])),
                    Err(Denial::BindingMismatch)
                ),
                "{} must bind evidence to the stored challenge context",
                vector["id"]
            );
        }
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
    assert_bundle_rejections(&vectors["bundleRejections"]);
}

#[test]
fn graph_rejection_vectors_refuse_self_edges_and_cycles() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../vectors/bcap1-graph-rejections.json"))
            .expect("vectors");
    assert_eq!(
        vectors["format"].as_str(),
        Some("bcap1-graph-rejections-v1")
    );
    assert_bundle_rejections(&vectors["bundleRejections"]);
}

#[test]
fn bundle_precedence_vectors_pick_the_shared_denial() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../vectors/bcap1-bundle-precedence.json"
    ))
    .expect("vectors");
    assert_eq!(
        vectors["format"].as_str(),
        Some("bcap1-bundle-precedence-v1")
    );
    assert_bundle_rejections(&vectors["cases"]);
}

fn assert_bundle_rejections(cases: &Value) {
    for rejection in cases.as_array().expect("bundle rejection cases") {
        let expected = match rejection["denial"].as_str() {
            Some("malformed") => Denial::Malformed,
            Some("resource_limit") => Denial::ResourceLimit,
            Some("unsupported_version") => Denial::UnsupportedVersion,
            value => panic!("unsupported denial vector {value:?}"),
        };
        assert_eq!(
            vector_bundle(rejection).validate(),
            Err(expected),
            "{}",
            rejection["id"]
        );
    }
}

fn usize_field(value: &Value) -> Option<usize> {
    value
        .as_u64()
        .map(|value| usize::try_from(value).expect("usize"))
}

/// Builds the bundle a rejection/precedence vector describes. Mirrors the
/// TypeScript builder in `typescript/test/core.test.ts`.
fn vector_bundle(rejection: &Value) -> EvidenceBundle {
    let evidence_bytes = usize_field(&rejection["evidenceBytesPerComponent"]).unwrap_or(1);
    let metadata_entries = usize_field(&rejection["metadataEntries"]).unwrap_or(0);
    let mut components: Vec<EvidenceComponent> = rejection["componentIds"]
        .as_array()
        .expect("component ids")
        .iter()
        .enumerate()
        .map(|(index, id)| EvidenceComponent {
            component_id: id.as_str().expect("component id").to_owned(),
            provider: "fixture-v1".into(),
            media_type: "application/fixture".into(),
            evidence: B64Url::from_bytes(&vec![1; evidence_bytes]),
            endorsements: None,
            untrusted_metadata: (index == 0 && metadata_entries > 0).then(|| {
                (0..metadata_entries)
                    .map(|entry| (format!("key-{entry}"), "value".to_owned()))
                    .collect::<BTreeMap<_, _>>()
            }),
        })
        .collect();
    for change in rejection["componentOverrides"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let component = &mut components[usize_field(&change["index"]).expect("index")];
        if let Some(media_type) = change["mediaType"].as_str() {
            component.media_type = media_type.to_owned();
        }
        if let Some(bytes) = usize_field(&change["evidenceBytes"]) {
            component.evidence = B64Url::from_bytes(&vec![1; bytes]);
        }
        if let Some(key) = change["metadataKey"].as_str() {
            component.untrusted_metadata =
                Some(BTreeMap::from([(key.to_owned(), "value".to_owned())]));
        }
    }
    let mut edges: Vec<EvidenceBindingEdge> = rejection["edges"]
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
            evidence: usize_field(&edge["evidenceBytes"])
                .map(|bytes| B64Url::from_bytes(&vec![1; bytes])),
        })
        .collect();
    for _ in 0..usize_field(&rejection["generatedEdges"]).unwrap_or(0) {
        edges.push(EvidenceBindingEdge {
            parent_component_id: "generated-parent".into(),
            child_component_id: "generated-child".into(),
            relation: "relation-a".into(),
            evidence: None,
        });
    }
    let subject = &rejection["subject"];
    EvidenceBundle {
        protocol_version: rejection["protocolVersion"]
            .as_u64()
            .map_or(1, |version| u8::try_from(version).expect("u8")),
        challenge_id: B64Url::from_bytes(&[0; 16]),
        subject: AttestationSubject {
            kind: subject["type"].as_str().unwrap_or("did").into(),
            value: subject["value"].as_str().unwrap_or("peer").into(),
        },
        components,
        binding_edges: Some(edges),
    }
}

#[test]
fn bundle_decode_precedence_vectors_pick_the_shared_denial() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../vectors/bcap1-bundle-decode-precedence.json"
    ))
    .expect("vectors");
    assert_eq!(
        vectors["format"].as_str(),
        Some("bcap1-bundle-decode-precedence-v1")
    );
    // The base must be accepted, or every case would pass vacuously.
    decode_bundle(vectors["base"].clone()).expect("valid base bundle");
    for case in vectors["cases"].as_array().expect("cases") {
        let mut bundle = vectors["base"].clone();
        for mutation in case["mutations"].as_array().expect("mutations") {
            apply_mutation(&mut bundle, mutation);
        }
        let expected = match case["denial"].as_str() {
            Some("malformed") => Denial::Malformed,
            Some("resource_limit") => Denial::ResourceLimit,
            Some("unsupported_version") => Denial::UnsupportedVersion,
            value => panic!("unsupported denial vector {value:?}"),
        };
        assert_eq!(decode_bundle(bundle), Err(expected), "{}", case["id"]);
    }
}

/// The transport's decode path: strict serde (a decode failure is malformed),
/// then validation.
fn decode_bundle(value: Value) -> Result<(), Denial> {
    let bundle: EvidenceBundle = serde_json::from_value(value).map_err(|_| Denial::Malformed)?;
    bundle.validate()
}

fn value_at<'a>(value: &'a mut Value, path: &str) -> (&'a mut Value, String) {
    let mut parts = path.split('.').collect::<Vec<_>>();
    let last = parts.pop().expect("path").to_owned();
    let mut current = value;
    for part in parts {
        current = match part.parse::<usize>() {
            Ok(index) => &mut current[index],
            Err(_) => &mut current[part],
        };
    }
    (current, last)
}

fn apply_mutation(bundle: &mut Value, mutation: &Value) {
    let replacement = match mutation["op"].as_str().expect("op") {
        "set" => mutation["value"].clone(),
        "repeat" => Value::String(format!(
            "{}{}{}",
            mutation["prefix"].as_str().unwrap_or_default(),
            mutation["character"].as_str().expect("character").repeat(
                usize::try_from(mutation["count"].as_u64().expect("count")).expect("usize")
            ),
            mutation["suffix"].as_str().unwrap_or_default(),
        )),
        op @ ("cloneComponents" | "cloneEdges") => {
            let key = if op == "cloneComponents" {
                "components"
            } else {
                "bindingEdges"
            };
            let first = bundle[key][0].clone();
            let count = mutation["count"].as_u64().expect("count");
            bundle[key] = Value::Array(
                (0..count)
                    .map(|index| {
                        let mut copy = first.clone();
                        if op == "cloneComponents" {
                            copy["componentId"] = Value::String(format!("c{index}"));
                        }
                        copy
                    })
                    .collect(),
            );
            return;
        }
        op => panic!("unsupported mutation {op}"),
    };
    let (parent, last) = value_at(bundle, mutation["path"].as_str().expect("path"));
    match last.parse::<usize>() {
        Ok(index) => parent[index] = replacement,
        Err(_) => {
            parent
                .as_object_mut()
                .expect("object")
                .insert(last, replacement);
        }
    }
}
