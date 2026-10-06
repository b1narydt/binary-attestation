//! In-TEE producer for the `dstack-attest-v0` profile (feature `producer`).
//!
//! Talks to the dstack 0.5.x guest agent over its Unix socket with a minimal
//! HTTP/1.1 client: `POST /Attest {"report_data": hex(binding)}` for the
//! parent and `POST /GetKey {path, purpose, algorithm}` for the frozen-v0
//! identity key, from which it derives the public key, signs the subject
//! proof and assembles the child plus the relation edge. The private key is
//! zeroized on every path and never appears in errors or output.

use std::path::{Path, PathBuf};

use binary_attestation_core::{B64Url, EvidenceBindingEdge, EvidenceComponent};
use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use zeroize::Zeroizing;

use crate::{
    DSTACK_ATTEST_V0_MEDIA_TYPE, DSTACK_ATTEST_V0_PROVIDER, DSTACK_SUBJECT_KEY_BRC100_RELATION,
    DSTACK_SUBJECT_KEY_MEDIA_TYPE, DSTACK_SUBJECT_KEY_V0_PROVIDER, SubjectKeyEvidence, hex,
    scale::LegacyAttestationV0, subject_proof_digest,
};

pub const DEFAULT_DSTACK_SOCKET: &str = "/var/run/dstack.sock";
pub const DSTACK_CVM_COMPONENT_ID: &str = "dstack-cvm";
pub const DSTACK_SUBJECT_KEY_COMPONENT_ID: &str = "dstack-subject-key";
/// Frozen-v0 request; only `purpose` is authenticated by the chain.
pub const IDENTITY_KEY_PATH: &str = "brc100-identity";
pub const IDENTITY_KEY_ALGORITHM: &str = "secp256k1";
/// Largest guest-agent response accepted.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProduceError {
    #[error("dstack guest agent socket {path} unavailable: {reason}")]
    SocketUnavailable { path: String, reason: String },
    #[error("dstack guest agent transport: {0}")]
    Transport(String),
    /// The agent answered but not with what the profile needs. Never carries
    /// a response body.
    #[error("dstack guest agent: {0}")]
    Agent(String),
    #[error("assembling evidence: {0}")]
    Internal(String),
}

/// The two components and the edge a relying party needs, plus the attested
/// public key so the caller can issue/compare the BRC-100 subject.
#[derive(Debug, Clone)]
pub struct ProducedEvidence {
    pub parent: EvidenceComponent,
    pub child: EvidenceComponent,
    pub edge: EvidenceBindingEdge,
    pub public_key: String,
}

#[derive(Deserialize)]
struct AttestResponse {
    attestation: String,
}

#[derive(Deserialize)]
struct GetKeyResponse {
    key: String,
    signature_chain: Vec<String>,
}

pub struct DstackAttestV0Producer {
    socket_path: PathBuf,
}

impl Default for DstackAttestV0Producer {
    fn default() -> Self {
        Self::new(DEFAULT_DSTACK_SOCKET)
    }
}

impl DstackAttestV0Producer {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    pub async fn produce(
        &self,
        binding_digest: [u8; 64],
    ) -> Result<ProducedEvidence, ProduceError> {
        let attest: AttestResponse = self
            .post_json(
                "/Attest",
                &serde_json::json!({ "report_data": hex::encode(&binding_digest) }),
            )
            .await?;
        let envelope = hex::decode_any(&attest.attestation)
            .ok_or_else(|| ProduceError::Agent("/Attest attestation is not hex".into()))?;
        let decoded = LegacyAttestationV0::decode(&envelope)
            .map_err(|denial| ProduceError::Agent(format!("/Attest envelope: {denial}")))?;
        if decoded.report_data != binding_digest {
            return Err(ProduceError::Agent(
                "/Attest report_data is not the BCAP1 binding digest".into(),
            ));
        }

        let get_key: GetKeyResponse = self
            .post_json(
                "/GetKey",
                &serde_json::json!({
                    "path": IDENTITY_KEY_PATH,
                    "purpose": crate::SUBJECT_KEY_PURPOSE,
                    "algorithm": IDENTITY_KEY_ALGORITHM,
                }),
            )
            .await?;
        let mut key_hex = Zeroizing::new(get_key.key);
        let key_bytes = Zeroizing::new(
            hex::decode_any(&key_hex)
                .ok_or_else(|| ProduceError::Agent("/GetKey key is not hex".into()))?,
        );
        key_hex.clear();
        let signing_key = SigningKey::from_slice(&key_bytes)
            .map_err(|_| ProduceError::Agent("/GetKey key is not a secp256k1 scalar".into()))?;
        drop(key_bytes);
        if get_key.signature_chain.len() != 2 {
            return Err(ProduceError::Agent(
                "/GetKey signature_chain is not the frozen-v0 two-link chain".into(),
            ));
        }
        let chain = get_key
            .signature_chain
            .iter()
            .map(|link| {
                hex::decode_any(link)
                    .filter(|bytes| bytes.len() == 65)
                    .map(|bytes| B64Url::from_bytes(&bytes))
                    .ok_or_else(|| {
                        ProduceError::Agent("/GetKey chain link is not 65 hex bytes".into())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let public_key = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        let signature: k256::ecdsa::Signature = signing_key
            .sign_prehash(&subject_proof_digest(&binding_digest))
            .map_err(|_| ProduceError::Internal("subject proof signing failed".into()))?;
        let signature = signature.normalize_s().unwrap_or(signature);
        drop(signing_key);
        let evidence = SubjectKeyEvidence {
            public_key: public_key.clone(),
            signature: B64Url::from_bytes(signature.to_der().as_bytes()),
            key_claim: B64Url::from_bytes(&SubjectKeyEvidence::key_claim_for(&public_key)),
            signature_chain: chain,
        }
        .to_jcs()
        .map_err(|denial| ProduceError::Internal(format!("child evidence: {denial}")))?;

        Ok(ProducedEvidence {
            parent: EvidenceComponent {
                component_id: DSTACK_CVM_COMPONENT_ID.into(),
                provider: DSTACK_ATTEST_V0_PROVIDER.into(),
                media_type: DSTACK_ATTEST_V0_MEDIA_TYPE.into(),
                evidence: B64Url::from_bytes(&envelope),
                endorsements: None,
                untrusted_metadata: None,
            },
            child: EvidenceComponent {
                component_id: DSTACK_SUBJECT_KEY_COMPONENT_ID.into(),
                provider: DSTACK_SUBJECT_KEY_V0_PROVIDER.into(),
                media_type: DSTACK_SUBJECT_KEY_MEDIA_TYPE.into(),
                evidence: B64Url::from_bytes(&evidence),
                endorsements: None,
                untrusted_metadata: None,
            },
            edge: EvidenceBindingEdge {
                parent_component_id: DSTACK_CVM_COMPONENT_ID.into(),
                child_component_id: DSTACK_SUBJECT_KEY_COMPONENT_ID.into(),
                relation: DSTACK_SUBJECT_KEY_BRC100_RELATION.into(),
                evidence: None,
            },
            public_key,
        })
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> Result<T, ProduceError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|error| ProduceError::SocketUnavailable {
                path: self.socket_path.display().to_string(),
                reason: error.to_string(),
            })?;
        let payload = body.to_string();
        let request = format!(
            "POST {endpoint} HTTP/1.1\r\nHost: dstack\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| ProduceError::Transport(format!("write {endpoint}: {error}")))?;
        let mut response = Zeroizing::new(Vec::new());
        stream
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut response)
            .await
            .map_err(|error| ProduceError::Transport(format!("read {endpoint}: {error}")))?;
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(ProduceError::Transport(format!(
                "{endpoint}: response too large"
            )));
        }
        let (status, body) = parse_http_response(&response)
            .map_err(|error| ProduceError::Transport(format!("{endpoint}: {error}")))?;
        if status != 200 {
            return Err(ProduceError::Agent(format!(
                "{endpoint} returned HTTP {status}"
            )));
        }
        serde_json::from_slice(&body)
            .map_err(|_| ProduceError::Agent(format!("{endpoint} returned an unexpected body")))
    }
}

/// Splits an HTTP/1.1 response into status and body (Content-Length, chunked,
/// or read-to-close). Returns the body in a zeroizing buffer.
fn parse_http_response(raw: &[u8]) -> Result<(u16, Zeroizing<Vec<u8>>), String> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("no header/body separator")?;
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| "non-UTF-8 header")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("bad status line")?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| "bad content-length")?,
                );
            }
            "transfer-encoding" => chunked = value.trim().eq_ignore_ascii_case("chunked"),
            _ => {}
        }
    }
    let rest = &raw[head_end + 4..];
    let body = if chunked {
        decode_chunked(rest)?
    } else if let Some(length) = content_length {
        rest.get(..length).ok_or("truncated body")?.to_vec()
    } else {
        rest.to_vec()
    };
    Ok((status, Zeroizing::new(body)))
}

fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("chunked: missing size line")?;
        let size_line = std::str::from_utf8(&rest[..line_end]).map_err(|_| "chunked: bad size")?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "chunked: bad size")?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if rest.len() < size + 2 {
            return Err("chunked: truncated chunk".into());
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_parsing() {
        let (status, body) =
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((status, body.as_slice()), (200, &b"{}"[..]));
        let (_, body) = parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(body.as_slice(), b"{}");
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}").is_err());
        assert!(parse_http_response(b"garbage").is_err());
    }
}
