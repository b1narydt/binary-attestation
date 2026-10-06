# Snapshot-bound production dstack capture

This directory records the live #606 proof captured on 2026-10-06 UTC from
Phala Cloud node `prod9` (node 18), production `dstack-0.5.9`, with the probe
image pinned to registry manifest
`sha256:3a73dffe4bd8d344ffa54d451f7889066ea3a504ddf8e60296520cc8b63603be`.

The `bootstrap/` pass allowed through the real `CoreVerifier` with all measured
launch values pinned and discovered the separately exposed, unmeasured
`vm_config_sha256`. The `final/` pass rebuilt the canonical provider artifact
and signed-snapshot body with that digest pinned too, issued a fresh challenge,
captured a fresh TDX quote bound to the new snapshot trust digest, and returned
`allowed` through the complete provider, relation, and BRC-100 identity policy
pipeline.

`evidence-response.json` contains only public quote, certificate, measurement,
public-key, and signature material. The in-TEE `/GetKey` scalar never left the
CVM. The short-lived GitHub registry token and temporary GitHub Actions Phala
secret were revoked before these artifacts were committed.

The final artifact SHA-256 digests are:

- `challenge.json`: `7d4b0e765f28cb3f2d8b6a8e0bfc223a6c9609d1338947cf37a5ee4e6683803f`
- `evidence-response.json`: `14ab8c936e79dfcc430565000766ac8bf974d008cf5415f7fc4aed310f2aee61`
- `policy-artifact.json`: `104f7c1a9a1e6e06e5ed1e2a9650afc0bcb4c0cb449ac28fdb06d5924d68ca0a`
- `snapshot.json`: `6a5c96f65f14fb1c886a95c6fbc5e91c1395aaa595f66b566508c4f7a198660f`

`rust/providers/dstack/tests/pipeline.rs` replays `final/` with a frozen trusted
clock and the production pinned collateral, then asserts the exact app,
compose, subject, and VM-config bindings through the real `CoreVerifier`.
