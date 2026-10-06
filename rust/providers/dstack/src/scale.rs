//! Bounded decoder for the dstack 0.5.x legacy SCALE V0 attestation envelope.
//!
//! Wire layout, verified against production 0.5.9 `/Attest` bytes:
//!
//! ```text
//! 00                                  LegacyVersionedAttestation::V0
//! 00                                  AttestationQuote::DstackTdx (the only accepted variant)
//! compact(len) || quote bytes         raw TDX v4 quote
//! compact(n) || TdxEvent * n          imr u32le || event_type u32le || digest Vec<u8> || event String || event_payload Vec<u8>
//! compact(n) || RuntimeEvent * n      event String || payload Vec<u8>
//! report_data [u8; 64]
//! compact(len) || config utf8         vm_config JSON
//! ```
//!
//! Every length is checked against the remaining input and a hard cap before
//! any allocation; the compact big-integer mode (`0b11`) is refused outright;
//! non-minimal compact encodings and trailing bytes are malformed.

use binary_attestation_core::{Denial, MAX_COMPONENT_EVIDENCE};

/// The envelope travels as one BCAP1 component, so the core's 2 MiB component
/// bound applies (dstack's own decoder caps at 10 MiB; the smaller wins).
pub const MAX_ENVELOPE_BYTES: usize = MAX_COMPONENT_EVIDENCE;
/// TDX v4 quotes with an embedded PCK chain are ~5 KiB; 64 KiB is generous.
pub const MAX_QUOTE_BYTES: usize = 64 * 1024;
/// Hard cap on entries in either event list.
pub const MAX_EVENTS: usize = 256;
pub const MAX_EVENT_NAME_BYTES: usize = 256;
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 64 * 1024;
/// SHA-384 digests are 48 bytes; anything larger is not a TDX event digest.
pub const MAX_EVENT_DIGEST_BYTES: usize = 64;
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

const VERSION_V0: u8 = 0;
const VARIANT_DSTACK_TDX: u8 = 0;

/// One TDX event-log entry as carried by the 0.5.x envelope. `digest` is
/// attacker-supplied and never trusted by the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxEvent {
    pub imr: u32,
    pub event_type: u32,
    pub digest: Vec<u8>,
    pub event: String,
    pub event_payload: Vec<u8>,
}

/// One runtime (RTMR3) event as carried by the 0.5.x envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event: String,
    pub payload: Vec<u8>,
}

/// Typed legacy V0 attestation (TDX variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyAttestationV0 {
    pub quote: Vec<u8>,
    pub tdx_events: Vec<TdxEvent>,
    pub runtime_events: Vec<RuntimeEvent>,
    pub report_data: [u8; 64],
    pub config: String,
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Denial> {
        if length > self.remaining() {
            return Err(Denial::Malformed);
        }
        let slice = &self.bytes[self.position..self.position + length];
        self.position += length;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, Denial> {
        Ok(self.take(1)?[0])
    }

    fn u32_le(&mut self) -> Result<u32, Denial> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// SCALE compact `u32` in modes `0b00`/`0b01`/`0b10`, minimal encoding
    /// required, value at most `cap`. Mode `0b11` is refused as a resource
    /// limit because no bounded field of this profile can need it.
    fn compact(&mut self, cap: usize) -> Result<usize, Denial> {
        let first = self.u8()?;
        let value = match first & 0b11 {
            0b00 => usize::from(first >> 2),
            0b01 => {
                let second = self.u8()?;
                let value = usize::from(u16::from_le_bytes([first, second]) >> 2);
                if value > cap {
                    return Err(Denial::ResourceLimit);
                }
                if value < 64 {
                    return Err(Denial::Malformed);
                }
                value
            }
            0b10 => {
                let rest = self.take(3)?;
                let value = u32::from_le_bytes([first, rest[0], rest[1], rest[2]]) >> 2;
                let value = usize::try_from(value).map_err(|_| Denial::ResourceLimit)?;
                if value > cap {
                    return Err(Denial::ResourceLimit);
                }
                if value < 16_384 {
                    return Err(Denial::Malformed);
                }
                value
            }
            _ => return Err(Denial::ResourceLimit),
        };
        if value > cap {
            return Err(Denial::ResourceLimit);
        }
        Ok(value)
    }

    fn bytes(&mut self, cap: usize) -> Result<Vec<u8>, Denial> {
        let length = self.compact(cap)?;
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, cap: usize) -> Result<String, Denial> {
        String::from_utf8(self.bytes(cap)?).map_err(|_| Denial::Malformed)
    }
}

impl LegacyAttestationV0 {
    /// Decodes a complete envelope; refuses other versions, other quote
    /// variants, over-cap lengths, truncation and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Denial> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Denial::ResourceLimit);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.u8()? != VERSION_V0 {
            return Err(Denial::UnsupportedVersion);
        }
        if reader.u8()? != VARIANT_DSTACK_TDX {
            return Err(Denial::UnsupportedProvider);
        }
        let quote = reader.bytes(MAX_QUOTE_BYTES)?;
        let tdx_count = reader.compact(MAX_EVENTS)?;
        let mut tdx_events = Vec::with_capacity(tdx_count);
        for _ in 0..tdx_count {
            tdx_events.push(TdxEvent {
                imr: reader.u32_le()?,
                event_type: reader.u32_le()?,
                digest: reader.bytes(MAX_EVENT_DIGEST_BYTES)?,
                event: reader.string(MAX_EVENT_NAME_BYTES)?,
                event_payload: reader.bytes(MAX_EVENT_PAYLOAD_BYTES)?,
            });
        }
        let runtime_count = reader.compact(MAX_EVENTS)?;
        let mut runtime_events = Vec::with_capacity(runtime_count);
        for _ in 0..runtime_count {
            runtime_events.push(RuntimeEvent {
                event: reader.string(MAX_EVENT_NAME_BYTES)?,
                payload: reader.bytes(MAX_EVENT_PAYLOAD_BYTES)?,
            });
        }
        let report_data: [u8; 64] = reader.take(64)?.try_into().map_err(|_| Denial::Malformed)?;
        let config = reader.string(MAX_CONFIG_BYTES)?;
        if reader.remaining() != 0 {
            return Err(Denial::Malformed);
        }
        Ok(Self {
            quote,
            tdx_events,
            runtime_events,
            report_data,
            config,
        })
    }

    /// Re-encodes the envelope (minimal compact lengths). Used by tests and
    /// producers; lengths above `2^30 - 1` are outside this profile and panic.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION_V0, VARIANT_DSTACK_TDX];
        push_bytes(&mut out, &self.quote);
        push_compact(&mut out, self.tdx_events.len());
        for event in &self.tdx_events {
            out.extend_from_slice(&event.imr.to_le_bytes());
            out.extend_from_slice(&event.event_type.to_le_bytes());
            push_bytes(&mut out, &event.digest);
            push_bytes(&mut out, event.event.as_bytes());
            push_bytes(&mut out, &event.event_payload);
        }
        push_compact(&mut out, self.runtime_events.len());
        for event in &self.runtime_events {
            push_bytes(&mut out, event.event.as_bytes());
            push_bytes(&mut out, &event.payload);
        }
        out.extend_from_slice(&self.report_data);
        push_bytes(&mut out, self.config.as_bytes());
        out
    }
}

fn push_compact(out: &mut Vec<u8>, value: usize) {
    assert!(
        value < (1 << 30),
        "SCALE compact length exceeds this profile's bounds"
    );
    let value = value as u32;
    if value < 64 {
        out.push((value << 2) as u8);
    } else if value < 16_384 {
        out.extend_from_slice(&(((value as u16) << 2) | 0b01).to_le_bytes());
    } else {
        out.extend_from_slice(&((value << 2) | 0b10).to_le_bytes());
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_compact(out, bytes.len());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> LegacyAttestationV0 {
        LegacyAttestationV0 {
            quote: vec![1, 2, 3],
            tdx_events: vec![TdxEvent {
                imr: 3,
                event_type: 0x0800_0001,
                digest: vec![],
                event: "system-ready".into(),
                event_payload: vec![],
            }],
            runtime_events: vec![RuntimeEvent {
                event: "system-ready".into(),
                payload: vec![],
            }],
            report_data: [7; 64],
            config: "{}".into(),
        }
    }

    #[test]
    fn round_trip_and_compact_modes() {
        let value = minimal();
        assert_eq!(LegacyAttestationV0::decode(&value.encode()).unwrap(), value);
        let mut long = minimal();
        long.quote = vec![9; 70];
        assert_eq!(LegacyAttestationV0::decode(&long.encode()).unwrap(), long);
        long.quote = vec![9; 20_000];
        assert_eq!(LegacyAttestationV0::decode(&long.encode()).unwrap(), long);
    }

    #[test]
    fn version_variant_trailing_and_truncation() {
        let bytes = minimal().encode();
        let mut other_version = bytes.clone();
        other_version[0] = 1;
        assert_eq!(
            LegacyAttestationV0::decode(&other_version),
            Err(Denial::UnsupportedVersion)
        );
        let mut other_variant = bytes.clone();
        other_variant[1] = 2;
        assert_eq!(
            LegacyAttestationV0::decode(&other_variant),
            Err(Denial::UnsupportedProvider)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            LegacyAttestationV0::decode(&trailing),
            Err(Denial::Malformed)
        );
        for cut in 0..bytes.len() {
            assert_eq!(
                LegacyAttestationV0::decode(&bytes[..cut]),
                Err(Denial::Malformed),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn caps_apply_before_allocation() {
        let mut bytes = vec![0, 0];
        bytes.extend_from_slice(&(((MAX_QUOTE_BYTES as u32 + 1) << 2) | 0b10).to_le_bytes());
        assert_eq!(
            LegacyAttestationV0::decode(&bytes),
            Err(Denial::ResourceLimit)
        );
        assert_eq!(
            LegacyAttestationV0::decode(&[0, 0, 0b11, 0, 0, 0, 0]),
            Err(Denial::ResourceLimit)
        );
        let oversized = vec![0; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            LegacyAttestationV0::decode(&oversized),
            Err(Denial::ResourceLimit)
        );
        // Event count at the cap plus one.
        let mut bytes = vec![0, 0, 0];
        bytes.extend_from_slice(&((((MAX_EVENTS as u16) + 1) << 2) | 0b01).to_le_bytes());
        assert_eq!(
            LegacyAttestationV0::decode(&bytes),
            Err(Denial::ResourceLimit)
        );
    }

    #[test]
    fn non_minimal_compact_is_malformed() {
        // Quote length 3 in two-byte mode.
        let mut bytes = vec![0, 0];
        bytes.extend_from_slice(&((3u16 << 2) | 0b01).to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        assert_eq!(LegacyAttestationV0::decode(&bytes), Err(Denial::Malformed));
        // Quote length 100 in four-byte mode.
        let mut bytes = vec![0, 0];
        bytes.extend_from_slice(&((100u32 << 2) | 0b10).to_le_bytes());
        bytes.extend_from_slice(&[0; 100]);
        assert_eq!(LegacyAttestationV0::decode(&bytes), Err(Denial::Malformed));
    }

    #[test]
    fn invalid_utf8_event_name_is_malformed() {
        let mut value = minimal();
        value.tdx_events[0].event = "ok".into();
        let mut bytes = value.encode();
        let position = bytes.windows(2).position(|w| w == b"ok").unwrap();
        bytes[position] = 0xff;
        assert_eq!(LegacyAttestationV0::decode(&bytes), Err(Denial::Malformed));
    }
}
