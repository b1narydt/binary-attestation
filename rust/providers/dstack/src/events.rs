//! dstack 0.5.x runtime (RTMR3) event replay and the pinned launch profile.
//!
//! Runtime events use `event_type = 0x08000001` and event-log version 1:
//! `digest = SHA-384(u32_le(0x08000001) || ":" || event || ":" || payload)`;
//! RTMR3 is `fold(SHA-384(mr || digest))` from 48 zero bytes. Supplied digest
//! fields are never an input.

use binary_attestation_core::Denial;
use serde::Deserialize;
use sha2::{Digest, Sha384};

use crate::hex;

/// dstack's event type for runtime (RTMR3) events.
pub const RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;
/// The TDX register runtime events extend.
pub const RUNTIME_EVENT_IMR: u32 = 3;
/// Exact dstack 0.5.9 launch order: no extras, no omissions, each once.
pub const LAUNCH_EVENT_ORDER: [&str; 10] = [
    "system-preparing",
    "app-id",
    "compose-hash",
    "instance-id",
    "boot-mr-done",
    "mr-kms",
    "os-image-hash",
    "key-provider",
    "storage-fs",
    "system-ready",
];
/// The only key provider this profile admits.
pub const KEY_PROVIDER_NAME: &str = "kms";

/// `SHA-384(u32_le(0x08000001) || ":" || event || ":" || payload)`.
pub fn runtime_event_digest(event: &str, payload: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(RUNTIME_EVENT_TYPE.to_le_bytes());
    hasher.update(b":");
    hasher.update(event.as_bytes());
    hasher.update(b":");
    hasher.update(payload);
    hasher.finalize().into()
}

/// Replays RTMR3 from zero over `digests` in order.
pub fn replay_rtmr3(digests: impl IntoIterator<Item = [u8; 48]>) -> [u8; 48] {
    let mut register = [0u8; 48];
    for digest in digests {
        let mut hasher = Sha384::new();
        hasher.update(register);
        hasher.update(digest);
        register = hasher.finalize().into();
    }
    register
}

/// Quote-authenticated launch values parsed from the pinned event sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchEvents {
    pub app_id: [u8; 20],
    pub compose_hash: [u8; 32],
    /// `instance-id` is 20 bytes or empty on 0.5.9.
    pub instance_id: Option<[u8; 20]>,
    pub mr_kms: [u8; 32],
    pub os_image_hash: [u8; 32],
    /// `key-provider` id: the KMS CA SubjectPublicKeyInfo DER.
    pub key_provider_id: Vec<u8>,
    pub storage_fs: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyProviderPayload {
    name: String,
    id: String,
}

/// Checks the exact launch order and payload shapes. Order/multiplicity
/// defects are `measurement_mismatch` (the measured sequence is not the
/// pinned profile); payload shape defects are `malformed`; a key provider
/// other than `kms` is `root_untrusted`.
pub fn parse_launch_events(events: &[(String, Vec<u8>)]) -> Result<LaunchEvents, Denial> {
    if events.len() != LAUNCH_EVENT_ORDER.len()
        || events
            .iter()
            .zip(LAUNCH_EVENT_ORDER)
            .any(|((event, _), expected)| event != expected)
    {
        return Err(Denial::MeasurementMismatch);
    }
    let payload = |index: usize| events[index].1.as_slice();
    for marker in [0usize, 4, 9] {
        if !payload(marker).is_empty() {
            return Err(Denial::Malformed);
        }
    }
    let app_id: [u8; 20] = payload(1).try_into().map_err(|_| Denial::Malformed)?;
    let compose_hash: [u8; 32] = payload(2).try_into().map_err(|_| Denial::Malformed)?;
    let instance_id = match payload(3) {
        [] => None,
        bytes => Some(bytes.try_into().map_err(|_| Denial::Malformed)?),
    };
    let mr_kms: [u8; 32] = payload(5).try_into().map_err(|_| Denial::Malformed)?;
    let os_image_hash: [u8; 32] = payload(6).try_into().map_err(|_| Denial::Malformed)?;
    let key_provider: KeyProviderPayload =
        serde_json::from_slice(payload(7)).map_err(|_| Denial::Malformed)?;
    let key_provider_id = hex::decode_lower(&key_provider.id).ok_or(Denial::Malformed)?;
    if key_provider_id.is_empty() {
        return Err(Denial::Malformed);
    }
    if key_provider.name != KEY_PROVIDER_NAME {
        return Err(Denial::RootUntrusted);
    }
    Ok(LaunchEvents {
        app_id,
        compose_hash,
        instance_id,
        mr_kms,
        os_image_hash,
        key_provider_id,
        storage_fs: payload(8).to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_like() -> Vec<(String, Vec<u8>)> {
        vec![
            ("system-preparing".into(), vec![]),
            ("app-id".into(), vec![1; 20]),
            ("compose-hash".into(), vec![2; 32]),
            ("instance-id".into(), vec![3; 20]),
            ("boot-mr-done".into(), vec![]),
            ("mr-kms".into(), vec![4; 32]),
            ("os-image-hash".into(), vec![5; 32]),
            (
                "key-provider".into(),
                br#"{"name":"kms","id":"3059"}"#.to_vec(),
            ),
            ("storage-fs".into(), b"zfs".to_vec()),
            ("system-ready".into(), vec![]),
        ]
    }

    #[test]
    fn parses_the_pinned_profile() {
        let parsed = parse_launch_events(&live_like()).unwrap();
        assert_eq!(parsed.app_id, [1; 20]);
        assert_eq!(parsed.instance_id, Some([3; 20]));
        assert_eq!(parsed.key_provider_id, vec![0x30, 0x59]);
        let mut empty_instance = live_like();
        empty_instance[3].1.clear();
        assert_eq!(
            parse_launch_events(&empty_instance).unwrap().instance_id,
            None
        );
    }

    #[test]
    fn order_and_shape_defects() {
        let mut swapped = live_like();
        swapped.swap(5, 6);
        assert_eq!(
            parse_launch_events(&swapped),
            Err(Denial::MeasurementMismatch)
        );
        let mut missing = live_like();
        missing.remove(0);
        assert_eq!(
            parse_launch_events(&missing),
            Err(Denial::MeasurementMismatch)
        );
        let mut marker = live_like();
        marker[9].1 = vec![1];
        assert_eq!(parse_launch_events(&marker), Err(Denial::Malformed));
        let mut other_provider = live_like();
        other_provider[7].1 = br#"{"name":"local","id":"3059"}"#.to_vec();
        assert_eq!(
            parse_launch_events(&other_provider),
            Err(Denial::RootUntrusted)
        );
        let mut uppercase_id = live_like();
        uppercase_id[7].1 = br#"{"name":"kms","id":"3A"}"#.to_vec();
        assert_eq!(parse_launch_events(&uppercase_id), Err(Denial::Malformed));
    }

    #[test]
    fn replay_is_order_sensitive() {
        let a = runtime_event_digest("a", b"1");
        let b = runtime_event_digest("b", b"2");
        assert_ne!(replay_rtmr3([a, b]), replay_rtmr3([b, a]));
        assert_eq!(replay_rtmr3([]), [0; 48]);
    }
}
