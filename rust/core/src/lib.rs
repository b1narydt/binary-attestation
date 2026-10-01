//! Provider-neutral implementation of the Binary Confidential Attestation
//! Protocol v1 (BCAP1) A0/A1 core.
//!
//! This crate deliberately contains neither evidence producers nor provider
//! runtimes.  Callers register independently audited verifiers and policies.
//! In particular, a successful [`VerifiedClaims`] is an in-process decision,
//! not a capability-release credential.

#![forbid(unsafe_code)]

mod canonical;
mod denial;
mod lifecycle;
mod provider;
mod snapshot;
mod transcript;
mod transport;
mod types;
mod verify;

pub use canonical::jcs_bytes;
pub use denial::Denial;
pub use lifecycle::{
    ChallengeState, ChallengeStore, Clock, DEFAULT_MAX_CLOCK_SKEW_MS, SystemClock,
};
pub use provider::{
    BindingRelationVerifier, EvidenceVerifier, PolicyDecision, PolicyEvaluator, ProviderRegistry,
    RelationRegistry,
};
pub use snapshot::{InMemorySnapshotStore, SecuritySnapshotStore, TerminalFence};
pub use transcript::{TranscriptPreimage, binding_digest, provider_binding_digest};
pub use transport::{
    AuthenticatedAttestationChannel, AuthenticatedMessage, AuthenticatedTransportMessage,
    ChannelFuture, MessageType, TransportMessage, TransportProfile,
};
pub use types::*;
pub use verify::{CoreVerifier, VerificationInput};
