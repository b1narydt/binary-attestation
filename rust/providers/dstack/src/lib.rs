//! BCAP1 provider for dstack 0.5.x TDX workloads (`dstack-attest-v0`, spec
//! §5.3 / §11.1) with the frozen-v0 `GetKey` subject-key relation
//! `dstack-subject-key-brc100-v1` (§6.2) and a reusable BRC-100 identity
//! policy.
//!
//! # Components and media types
//!
//! | Role | Provider / relation | Media type |
//! |---|---|---|
//! | CVM evidence (parent) | [`DSTACK_ATTEST_V0_PROVIDER`] | [`DSTACK_ATTEST_V0_MEDIA_TYPE`]: the raw `/Attest` response, a legacy SCALE V0 `VersionedAttestation` (TDX variant only). |
//! | Subject key (child) | [`DSTACK_SUBJECT_KEY_V0_PROVIDER`] | [`DSTACK_SUBJECT_KEY_MEDIA_TYPE`]: RFC 8785 JCS bytes of the §6.2 object. |
//! | Relation edge | [`DSTACK_SUBJECT_KEY_BRC100_RELATION`] | none (edge evidence must be absent). |
//!
//! The child's `keyClaim` for frozen v0 is exactly the link-0 preimage bytes
//! `UTF8("identity:" || lowercase_hex(public_key))`; see [`subject_key`].
//!
//! # Verification order of the parent (fail-cheap, fail-closed)
//!
//! 1. component shape: provider/media type, no endorsements, evidence bound;
//! 2. bounded SCALE V0 decode ([`scale`]), version/variant checks, no trailing
//!    bytes;
//! 3. structural launch checks: the `imr == 3` `TdxEvent`s and the
//!    `RuntimeEvent` list must agree exactly; the pinned 0.5.9 launch order
//!    must match exactly ([`events`]);
//! 4. envelope `report_data == expected_binding` (constant time);
//! 5. FMSPC selection of pinned collateral, collateral window, DCAP quote
//!    verification (`dcap-qvl`, Intel production root by default);
//! 6. authenticated `report_data == expected_binding` (constant time), TCB
//!    allowlist;
//! 7. RTMR3 replay from recomputed digests (`SHA-384(u32_le(0x08000001) ||
//!    ":" || event || ":" || payload)`) equals the authenticated register;
//!    supplied `digest` fields are ignored;
//! 8. `mr_config_id == 0x01 || compose_hash || 0`, `key-provider.id ==` pinned
//!    KMS CA SPKI, optional `mr-kms` pin, `os_image_hash` allowlist, optional
//!    compose-hash / app-id allowlists, `vm_config.os_image_hash` consistency;
//! 9. normalized measurements and `valid_until_ms` capped at the pinned
//!    collateral's earliest expiry.
//!
//! The child never binds the BCAP1 digest directly (its `binding_digest` is
//! all zero) so the core accepts it only through a verified relation edge from
//! a bound dstack parent.
//!
//! Production core verifiers should construct the parent, child, relation and
//! policy together with [`DstackSnapshotPlugins::from_snapshot`]. Its canonical
//! provider artifact commits collateral, roots, TCB/advisory posture and the
//! complete workload/boot allowlists to the challenge's `trustDigest`.

#![forbid(unsafe_code)]

mod attest;
mod chain;
pub mod collateral;
pub mod events;
mod hex;
mod policy;
#[cfg(feature = "producer")]
pub mod producer;
mod relation;
pub mod scale;
mod snapshot;
mod subject_key_verifier;
mod trust;

pub use attest::{DSTACK_ATTEST_V0_MEDIA_TYPE, DSTACK_ATTEST_V0_PROVIDER, DstackAttestV0Verifier};
pub use collateral::PinnedCollateral;
pub use policy::{BootMeasurements, DstackBrc100IdentityPolicy};
pub use relation::{DSTACK_SUBJECT_KEY_BRC100_RELATION, DstackSubjectKeyBrc100Relation};
pub use snapshot::{
    DSTACK_POLICY_ARTIFACT_CANONICALIZATION, DSTACK_POLICY_ARTIFACT_MEDIA_TYPE, DcapRootV1,
    DstackPolicyArtifactV1, DstackSnapshotPlugins,
};
pub use subject_key_verifier::{
    DSTACK_SUBJECT_KEY_MEDIA_TYPE, DSTACK_SUBJECT_KEY_V0_PROVIDER, DstackSubjectKeyV0Verifier,
    SUBJECT_KEY_PURPOSE, SubjectKeyEvidence, subject_proof_digest,
};
pub use trust::{DstackTrust, KmsPins};

/// Frozen-v0 `GetKey` subject-key child (`dstack-subject-key-v0`).
///
/// Decoded evidence is the RFC 8785 JCS encoding of
///
/// ```json
/// {
///   "publicKey": "<66 lowercase hex, compressed secp256k1>",
///   "signature": "<base64url strict-DER low-S ECDSA over subject_proof_digest>",
///   "keyClaim": "<base64url of UTF8(\"identity:\" || publicKey)>",
///   "signatureChain": ["<base64url 65-byte r||s||v link 0>", "<... link 1>"]
/// }
/// ```
///
/// `keyClaim` is defined as the exact link-0 preimage dstack 0.5.x signs:
/// `purpose || ":" || lowercase_hex(public_key)` with `purpose = "identity"`.
/// Link 0 is a recoverable secp256k1 signature by the app root over
/// `keccak256(keyClaim)`; link 1 is the KMS secp256k1 root's signature over
/// `keccak256("dstack-kms-issued:" || app_id || app_root)`, verified by the
/// relation with the quote-authenticated `app_id` of the parent.
pub mod subject_key {
    pub use crate::subject_key_verifier::*;
}
