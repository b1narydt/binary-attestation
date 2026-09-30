use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AttestationSubject, B64Url, Challenge, Denial, EvidenceBundle, PROTOCOL_VERSION,
    constant_time_eq, jcs_bytes,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProfile {
    Brc103WebsocketV1,
    Brc104HttpsV1,
    Brc103AtlasMessageboxV1,
}

/// A peer identity derived by a mutually authenticated carrier, never an
/// asserted envelope field.
#[derive(Debug, Clone)]
pub struct AuthenticatedMessage<T> {
    pub authenticated_peer: AttestationSubject,
    pub transport_profile: TransportProfile,
    pub message_id: B64Url,
    pub payload: T,
}

pub type ChannelFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Denial>> + Send + 'a>>;

/// Transport-neutral BCAP1 authenticated channel (§12). Implementations must
/// authenticate their registered carrier before exposing a message here. This
/// provider-neutral crate deliberately includes no network implementation.
pub trait AuthenticatedAttestationChannel: Send + Sync {
    fn local_subject(&self) -> &AttestationSubject;
    fn profile(&self) -> TransportProfile;

    fn send_challenge(
        &self,
        peer: AttestationSubject,
        challenge: Challenge,
    ) -> ChannelFuture<'_, ()>;
    fn receive_challenge(&self) -> ChannelFuture<'_, AuthenticatedMessage<Challenge>>;
    fn send_evidence(
        &self,
        peer: AttestationSubject,
        bundle: EvidenceBundle,
    ) -> ChannelFuture<'_, ()>;
    fn receive_evidence(&self) -> ChannelFuture<'_, AuthenticatedMessage<EvidenceBundle>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportMessage {
    pub protocol_version: u8,
    pub message_type: MessageType,
    pub message_id: B64Url,
    pub sender: AttestationSubject,
    pub recipient: AttestationSubject,
    pub context_digest: B64Url,
    pub payload_encoding: String,
    pub payload: B64Url,
    pub payload_digest: B64Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Challenge,
    Evidence,
}

/// A payload exposed only after the carrier has authenticated the peer and the
/// BCAP1 envelope has been structurally and cryptographically checked.
#[derive(Debug, Clone)]
pub enum AuthenticatedTransportMessage {
    Challenge {
        authenticated_peer: AttestationSubject,
        message_id: B64Url,
        challenge: Challenge,
    },
    Evidence {
        authenticated_peer: AttestationSubject,
        message_id: B64Url,
        bundle: EvidenceBundle,
        context_digest: B64Url,
    },
}

impl TransportMessage {
    pub fn decode(
        &self,
        authenticated_peer: AttestationSubject,
        local_subject: &AttestationSubject,
    ) -> Result<AuthenticatedTransportMessage, Denial> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(Denial::UnsupportedVersion);
        }
        self.sender.validate()?;
        self.recipient.validate()?;
        authenticated_peer.validate()?;
        local_subject.validate()?;
        if authenticated_peer != self.sender {
            return Err(Denial::SubjectUnauthenticated);
        }
        if &self.recipient != local_subject {
            return Err(Denial::SubjectMismatch);
        }
        if self.message_id.decoded_len() != 16
            || self.context_digest.decoded_len() != 32
            || self.payload_digest.decoded_len() != 32
            || self.payload_encoding != "rfc8785-jcs"
        {
            return Err(Denial::Malformed);
        }
        if self.payload.decoded_len() > crate::MAX_BUNDLE_BYTES {
            return Err(Denial::ResourceLimit);
        }
        let payload = self.payload.decode_with_limit(crate::MAX_BUNDLE_BYTES)?;
        if !constant_time_eq(
            &Sha256::digest(&payload),
            &self.payload_digest.bytes::<32>()?,
        ) {
            return Err(Denial::BindingMismatch);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| Denial::Malformed)?;
        if jcs_bytes(&value)? != payload {
            return Err(Denial::Malformed);
        }
        match self.message_type {
            MessageType::Challenge => {
                let challenge: Challenge =
                    serde_json::from_value(value).map_err(|_| Denial::Malformed)?;
                challenge.validate()?;
                if challenge.subject != self.recipient
                    || challenge.context_digest != self.context_digest
                {
                    return Err(Denial::SubjectMismatch);
                }
                Ok(AuthenticatedTransportMessage::Challenge {
                    authenticated_peer,
                    message_id: self.message_id.clone(),
                    challenge,
                })
            }
            MessageType::Evidence => {
                let bundle: EvidenceBundle =
                    serde_json::from_value(value).map_err(|_| Denial::Malformed)?;
                bundle.validate()?;
                if bundle.subject != self.sender {
                    return Err(Denial::SubjectMismatch);
                }
                Ok(AuthenticatedTransportMessage::Evidence {
                    authenticated_peer,
                    message_id: self.message_id.clone(),
                    bundle,
                    context_digest: self.context_digest.clone(),
                })
            }
        }
    }
}
