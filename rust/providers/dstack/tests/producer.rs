//! In-TEE producer (feature `producer`) against a hermetic fake dstack guest
//! agent on a Unix socket. The fake replays the live `/Attest` bytes and
//! answers `/GetKey` with a throwaway key, so the assembled bundle can be
//! checked for shape, canonical encoding and key hygiene without a TEE.
#![cfg(feature = "producer")]

mod common;

use std::{path::PathBuf, time::Duration};

use binary_attestation_core::{EvidenceVerifier, MAX_COMPONENT_EVIDENCE, jcs_bytes};
use binary_attestation_dstack::{
    DSTACK_ATTEST_V0_MEDIA_TYPE, DSTACK_ATTEST_V0_PROVIDER, DSTACK_SUBJECT_KEY_BRC100_RELATION,
    DSTACK_SUBJECT_KEY_MEDIA_TYPE, DSTACK_SUBJECT_KEY_V0_PROVIDER,
    producer::{DstackAttestV0Producer, ProduceError},
};
use common::*;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

struct FakeAgent {
    socket: PathBuf,
    app_key: SigningKey,
    identity_key: SigningKey,
    envelope: Vec<u8>,
    expected_report_data: String,
}

fn recoverable(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let (signature, recovery) = key
        .sign_prehash_recoverable(&Keccak256::digest(message))
        .expect("sign");
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    bytes
}

impl FakeAgent {
    fn spawn(self) -> tokio::task::JoinHandle<Vec<String>> {
        self.spawn_requests(2)
    }

    fn spawn_requests(self, request_count: usize) -> tokio::task::JoinHandle<Vec<String>> {
        let listener = UnixListener::bind(&self.socket).expect("bind");
        tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut raw = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await.expect("read");
                    raw.extend_from_slice(&buffer[..read]);
                    if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..end]).to_string();
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().expect("len"))
                            })
                            .expect("content-length");
                        if raw.len() >= end + 4 + length {
                            break;
                        }
                    }
                    if read == 0 {
                        break;
                    }
                }
                let end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
                let request_line = String::from_utf8_lossy(&raw[..end])
                    .lines()
                    .next()
                    .expect("request line")
                    .to_owned();
                let body: serde_json::Value =
                    serde_json::from_slice(&raw[end + 4..]).expect("json body");
                seen.push(request_line.clone());
                let response = if request_line.starts_with("POST /Attest ") {
                    assert_eq!(body["report_data"], self.expected_report_data);
                    serde_json::json!({ "attestation": hex_encode(&self.envelope) })
                } else if request_line.starts_with("POST /GetKey ") {
                    assert_eq!(
                        body,
                        serde_json::json!({
                            "path": "brc100-identity",
                            "purpose": "identity",
                            "algorithm": "secp256k1"
                        })
                    );
                    let public_key = hex_encode(
                        &self
                            .identity_key
                            .verifying_key()
                            .to_encoded_point(true)
                            .to_bytes(),
                    );
                    let link0 =
                        recoverable(&self.app_key, format!("identity:{public_key}").as_bytes());
                    let link1 = recoverable(&self.app_key, b"not-the-kms");
                    serde_json::json!({
                        "key": hex_encode(&self.identity_key.to_bytes()),
                        "signature_chain": [hex_encode(&link0), hex_encode(&link1)]
                    })
                } else {
                    serde_json::json!({ "error": "unexpected path" })
                };
                let payload = response.to_string();
                let http = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                stream.write_all(http.as_bytes()).await.expect("write");
                stream.shutdown().await.expect("shutdown");
            }
            seen
        })
    }
}

fn socket_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bcap1-dstack-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    dir
}

#[tokio::test]
async fn subject_public_key_returns_only_the_compressed_identity() {
    let probe = probe_did();
    let socket = socket_path("subject-public-key");
    let identity_key = SigningKey::from_slice(&[7u8; 32]).expect("key");
    let private_hex = hex_encode(&identity_key.to_bytes());
    let expected_public_key = hex_encode(
        &identity_key
            .verifying_key()
            .to_encoded_point(true)
            .to_bytes(),
    );
    let agent = FakeAgent {
        socket: socket.clone(),
        app_key: SigningKey::from_slice(&[9u8; 32]).expect("key"),
        identity_key,
        envelope: probe.envelope,
        expected_report_data: hex_encode(&probe.binding),
    }
    .spawn_requests(1);

    let public_key = DstackAttestV0Producer::new(&socket)
        .subject_public_key()
        .await
        .expect("public key");
    let seen = agent.await.expect("agent task");
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("POST /GetKey "));
    assert_eq!(public_key, expected_public_key);
    assert!(!public_key.contains(&private_hex));
    let _ = std::fs::remove_file(&socket);
}

#[tokio::test]
async fn producer_assembles_a_verifiable_pair_and_never_emits_the_private_key() {
    let probe = probe_did();
    let socket = socket_path("produce");
    let identity_key = SigningKey::from_slice(&[7u8; 32]).expect("key");
    let private_hex = hex_encode(&identity_key.to_bytes());
    let agent = FakeAgent {
        socket: socket.clone(),
        app_key: SigningKey::from_slice(&[9u8; 32]).expect("key"),
        identity_key: identity_key.clone(),
        envelope: probe.envelope.clone(),
        expected_report_data: hex_encode(&probe.binding),
    }
    .spawn();

    let produced = DstackAttestV0Producer::new(&socket)
        .produce(probe.binding)
        .await
        .expect("produce");
    let seen = agent.await.expect("agent task");
    assert_eq!(seen.len(), 2);
    assert!(seen[0].starts_with("POST /Attest "));
    assert!(seen[1].starts_with("POST /GetKey "));

    assert_eq!(produced.parent.provider, DSTACK_ATTEST_V0_PROVIDER);
    assert_eq!(produced.parent.media_type, DSTACK_ATTEST_V0_MEDIA_TYPE);
    assert_eq!(
        produced
            .parent
            .evidence
            .decode_with_limit(MAX_COMPONENT_EVIDENCE)
            .expect("bounded"),
        probe.envelope
    );
    assert_eq!(produced.child.provider, DSTACK_SUBJECT_KEY_V0_PROVIDER);
    assert_eq!(produced.child.media_type, DSTACK_SUBJECT_KEY_MEDIA_TYPE);
    assert_eq!(produced.edge.relation, DSTACK_SUBJECT_KEY_BRC100_RELATION);
    assert_eq!(
        produced.edge.parent_component_id,
        produced.parent.component_id
    );
    assert_eq!(
        produced.edge.child_component_id,
        produced.child.component_id
    );
    assert!(produced.edge.evidence.is_none());

    // The parent verifies as live evidence (it is the live envelope).
    attest_verifier()
        .verify(&produced.parent, probe.binding, probe.now_ms())
        .expect("parent verifies");
    // The child is JCS-canonical and its subject proof verifies for the key.
    let evidence = produced
        .child
        .evidence
        .decode_with_limit(MAX_COMPONENT_EVIDENCE)
        .expect("bounded");
    let value: serde_json::Value = serde_json::from_slice(&evidence).expect("json");
    assert_eq!(jcs_bytes(&value).expect("jcs"), evidence);
    let child = subject_key_verifier()
        .verify(&produced.child, probe.binding, probe.now_ms())
        .expect("child verifies");
    let expected_public_key = hex_encode(
        &identity_key
            .verifying_key()
            .to_encoded_point(true)
            .to_bytes(),
    );
    assert_eq!(produced.public_key, expected_public_key);
    assert_eq!(child.measurements["public_key"], expected_public_key);

    // Key hygiene: nothing the producer returns contains the private scalar.
    let serialized = format!(
        "{}{}{}{:?}",
        serde_json::to_string(&produced.parent).expect("json"),
        serde_json::to_string(&produced.child).expect("json"),
        serde_json::to_string(&produced.edge).expect("json"),
        produced
    );
    assert!(!serialized.contains(&private_hex));
    let _ = std::fs::remove_file(&socket);
}

#[tokio::test]
async fn producer_fails_closed_without_the_guest_agent_socket() {
    let probe = probe_did();
    let missing = socket_path("missing");
    let error = DstackAttestV0Producer::new(&missing)
        .produce(probe.binding)
        .await
        .expect_err("no socket");
    assert!(matches!(error, ProduceError::SocketUnavailable { .. }));
}

#[tokio::test]
async fn producer_refuses_an_attestation_whose_report_data_is_not_the_binding() {
    let did = probe_did();
    let brc100 = probe_brc100();
    let socket = socket_path("mismatch");
    let agent = FakeAgent {
        socket: socket.clone(),
        app_key: SigningKey::from_slice(&[9u8; 32]).expect("key"),
        identity_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
        envelope: brc100.envelope.clone(),
        expected_report_data: hex_encode(&did.binding),
    }
    .spawn();
    let error = DstackAttestV0Producer::new(&socket)
        .produce(did.binding)
        .await
        .expect_err("report_data mismatch");
    assert!(matches!(error, ProduceError::Agent(_)), "{error}");
    agent.abort();
    let _ = std::fs::remove_file(&socket);
}

#[tokio::test]
async fn producer_times_out_when_the_guest_agent_stalls() {
    let probe = probe_did();
    let socket = socket_path("timeout");
    let listener = UnixListener::bind(&socket).expect("bind");
    let stalled = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let error = DstackAttestV0Producer::new(&socket)
        .with_timeout(Duration::from_millis(20))
        .produce(probe.binding)
        .await
        .expect_err("stalled agent must time out");
    assert!(
        matches!(
            error,
            ProduceError::Timeout {
                ref endpoint,
                phase: "read"
            } if endpoint == "/Attest"
        ),
        "{error}"
    );
    stalled.abort();
    let _ = std::fs::remove_file(&socket);
}
