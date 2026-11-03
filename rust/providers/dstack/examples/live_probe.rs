//! Minimal in-CVM capture endpoint for the signed dstack #606 proof.
//!
//! `GET /identity` returns only the app-bound compressed BRC-100 public key.
//! `POST /evidence` accepts one canonical BCAP1 challenge and returns the
//! matching evidence bundle with Intel collateral from
//! `DSTACK_COLLATERAL_PATH`. Private key bytes never leave the guest agent or
//! this process and are never included in errors, responses, or logs.

use std::{fs, io, sync::Arc};

use binary_attestation_core::{Challenge, EvidenceBundle};
use binary_attestation_dstack::producer::DstackAttestV0Producer;
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityResponse {
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceResponse {
    public_key: String,
    binding_digest: String,
    bundle: EvidenceBundle,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let collateral_path = std::env::var("DSTACK_COLLATERAL_PATH").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DSTACK_COLLATERAL_PATH is required",
        )
    })?;
    let collateral = Arc::new(fs::read(collateral_path)?);
    let listener = TcpListener::bind("0.0.0.0:8000").await?;
    let producer = Arc::new(DstackAttestV0Producer::default());
    loop {
        let (stream, _) = listener.accept().await?;
        let producer = Arc::clone(&producer);
        let collateral = Arc::clone(&collateral);
        tokio::spawn(async move {
            if let Err(error) = serve(stream, producer, collateral).await {
                eprintln!("live probe request failed: {error}");
            }
        });
    }
}

async fn serve(
    mut stream: TcpStream,
    producer: Arc<DstackAttestV0Producer>,
    collateral: Arc<Vec<u8>>,
) -> Result<(), String> {
    let request = read_request(&mut stream).await?;
    let (status, response) = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/health") => (200, serde_json::json!({"ok": true})),
        ("GET", "/identity") => match producer.subject_public_key().await {
            Ok(public_key) => (
                200,
                serde_json::to_value(IdentityResponse { public_key })
                    .map_err(|error| error.to_string())?,
            ),
            Err(error) => (503, serde_json::json!({"error": error.to_string()})),
        },
        ("POST", "/evidence") => {
            match produce_evidence(&producer, &collateral, &request.body).await {
                Ok(response) => (
                    200,
                    serde_json::to_value(response).map_err(|error| error.to_string())?,
                ),
                Err(error) => (400, serde_json::json!({"error": error})),
            }
        }
        _ => (404, serde_json::json!({"error": "not found"})),
    };
    write_response(&mut stream, status, &response).await
}

async fn produce_evidence(
    producer: &DstackAttestV0Producer,
    collateral: &[u8],
    body: &[u8],
) -> Result<EvidenceResponse, String> {
    let challenge: Challenge =
        serde_json::from_slice(body).map_err(|_| "invalid challenge JSON".to_string())?;
    challenge
        .validate()
        .map_err(|denial| format!("invalid challenge: {denial}"))?;
    let binding = challenge
        .binding_digest()
        .map_err(|denial| format!("challenge binding: {denial}"))?;
    let evidence = producer
        .produce(binding, collateral)
        .await
        .map_err(|error| error.to_string())?;
    if challenge.subject.kind != "brc100-public-key"
        || challenge.subject.value != evidence.public_key
    {
        return Err("challenge subject is not this CVM's BRC-100 identity".into());
    }
    let bundle = EvidenceBundle {
        protocol_version: 1,
        challenge_id: challenge.challenge_id,
        subject: challenge.subject,
        components: vec![evidence.parent, evidence.child],
        binding_edges: Some(vec![evidence.edge]),
    };
    bundle
        .validate()
        .map_err(|denial| format!("assembled bundle: {denial}"))?;
    Ok(EvidenceResponse {
        public_key: evidence.public_key,
        binding_digest: hex(&binding),
        bundle,
    })
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut bytes = Vec::new();
    let mut scratch = [0u8; 4096];
    let header_end = loop {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("request exceeds limit".into());
        }
        let read = stream
            .read(&mut scratch)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed before headers".into());
        }
        bytes.extend_from_slice(&scratch[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "request headers are not UTF-8".to_string())?;
    let mut lines = header.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?
        .split_whitespace();
    let method = request_line
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_owned();
    let path = request_line
        .next()
        .ok_or_else(|| "missing path".to_string())?
        .to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|_| "invalid content length".to_string())?
        .unwrap_or(0);
    if content_length > MAX_REQUEST_BYTES || header_end + content_length > MAX_REQUEST_BYTES {
        return Err("request exceeds limit".into());
    }
    while bytes.len() < header_end + content_length {
        let read = stream
            .read(&mut scratch)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed before body".into());
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("request exceeds limit".into());
        }
    }
    Ok(Request {
        method,
        path,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &serde_json::Value,
) -> Result<(), String> {
    let body = serde_json::to_vec(body).map_err(|error| error.to_string())?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Service Unavailable",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&body)
        .await
        .map_err(|error| error.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
