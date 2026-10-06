# Binary confidential attestation

Binary Confidential Attestation Protocol v1 (BCAP1) is a provider-neutral
challenge, evidence, verification, policy, and authorization contract for
confidential workloads.

The relying party owns freshness and authorization. A carrier such as Atlas
MessageBox delivers opaque authenticated messages but does not verify evidence
or cache a trust verdict. Provider evidence authenticates the complete BCAP1
transcript digest: subject, audience, operation context, policy, security epoch,
fresh nonce, and expiry.

This repository owns:

- `spec/` — versioned JSON Schemas and the normative contract snapshot;
- `vectors/` — immutable cross-language known-answer and rejection vectors;
- `typescript/` — browser-safe `@binary/attestation` portable core;
- `rust/core/` — provider-neutral `binary-attestation-core`;
- `rust/providers/dstack/` — `binary-attestation-dstack`, the dstack 0.5.x
  `dstack-attest-v0` TDX/DCAP provider, the frozen-v0 `GetKey` subject-key
  relation and a BRC-100 identity policy (optional in-TEE `producer`);
- later provider/runtime packages for dstack 0.6+, DCAP, and NVIDIA evidence.

It does not own Atlas Relay behavior, MPC ceremonies, provider-native host
runtimes in browser packages, or capability/key release policy.

## Development

Prerequisites: current stable Rust, Node.js 22+, and pnpm 10+.

```bash
pnpm install --frozen-lockfile
bash scripts/baseline.sh
```

The first delivery gate is Atlas issue
[`#605`](https://github.com/project-at-las/Atlas-Documentation/issues/605):
A0 schemas/vectors followed by the hardware-free A1 state and policy core.

