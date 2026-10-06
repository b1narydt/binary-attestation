# dstack 0.5.9 production fixtures

Public evidence captured live on 2026-10-05/06 (UTC) from a Phala Cloud CVM
running the production `dstack-0.5.9` guest image. No private key material is
present: `identity.json` is the `GetKey` response with the `key` field removed
before it left the CVM, plus the public key and the subject-proof signature the
in-CVM probe computed.

| File | Source |
|---|---|
| `probe-did/`, `probe-brc100/` | Two BCAP1 challenges issued against the same CVM minutes apart. `challenge.json` is the issued challenge (`probe-did` subject `{type:"did",value:"bcap1-live-probe"}`; `probe-brc100` subject is the CVM's own BRC-100 identity key). `binding-digest.hex` is its SHA-512 transcript digest (tests recompute it). `attest-scale-v0.bin` is the raw `/Attest` response (legacy SCALE V0 envelope, TDX variant) with `report_data = binding digest`. `identity.json` is frozen-v0 `GetKey(path=brc100-identity, purpose=identity, algorithm=secp256k1)` without the key. `subject-proof-digest.hex` is `SHA-256("BINARY-BCAP1-SUBJECT-PROOF\0" ‖ binding_digest)`. |
| `collateral.json` | Intel DCAP collateral for FMSPC `20A06F000000` fetched from `https://pccs.phala.network` at capture time (binary fields hex-encoded; see `PinnedCollateral`). TCB info issued 2026-10-06T00:26:11Z, next update 2026-11-05T00:26:11Z. |
| `kms-meta.json` | Phala production KMS `GetMeta`: `ca_cert` (P-256 CA whose SPKI is the `key-provider` event id) and `k256_pubkey` (`0334c76e…`, the secp256k1 root link 1 recovers to). `bootstrap_info` is `null` on this KMS. |
| `info.json` | Guest `/Info` (`tcb_info` with the event log, `os_image_hash` `bd369a8c…`, `compose_hash`, `app_id`, `instance_id`). Used only to cross-check the verifier's normalized measurements. |

The challenges were issued by the live probe with
`trustDigest = SHA-256("live-probe-trust")`, i.e. not a commitment to a signed
security-snapshot body. The provider, relation and policy tests run on these
bytes; the `CoreVerifier` end-to-end test proves the core refuses such a
challenge before any plugin runs, and a future capture issued from a real
snapshot is needed for a full-core allow.
