# dstack live CoreVerifier proof

This disposable service captures the missing #606 proof: one production
dstack-0.5.9 quote for a challenge whose `trustDigest` is the digest of the
exact signed snapshot policy used by the real `CoreVerifier` allow path.

The probe exposes only:

- `GET /health`
- `GET /identity` — the compressed app-bound BRC-100 public key
- `POST /evidence` — a BCAP1 challenge in, its bound parent/child bundle out

It never returns or logs the `/GetKey` private scalar.

## Build and publish

Publish a single Linux/AMD64 manifest, then replace the compose image tag with
the immutable registry digest before deployment:

```bash
docker buildx build \
  --platform linux/amd64 \
  --provenance=false \
  --sbom=false \
  -f deploy/dstack-live-probe/Dockerfile \
  -t ghcr.io/b1narydt/bcap1-dstack-probe:20261005 \
  --push .
```

## Deploy

The release proof must pin production dstack, prod9, and the non-development
OS. Do not allow the CLI to auto-select the image or node.

```bash
phala deploy \
  --name bcap1-dstack-probe \
  --compose deploy/dstack-live-probe/docker-compose.yml \
  --instance-type tdx.small \
  --node-id 18 \
  --image dstack-0.5.9 \
  --no-dev-os \
  --wait \
  --json
```

Record the CVM/app/instance IDs, compose hash, exact image digest, OS image
hash, `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`, KMS metadata, collateral provenance,
and verifier commit. Refuse the capture if any expected production pin differs.

## Issue and verify

After constructing `policy-artifact.json` from those exact pins, fetch the
public identity, issue the snapshot-bound challenge, capture evidence, and run
the real verifier:

```bash
cargo run -p binary-attestation-dstack --example live_core_verifier -- \
  issue policy-artifact.json SUBJECT_PUBLIC_KEY capture-dir

curl -fsS -H 'content-type: application/json' \
  --data-binary @capture-dir/challenge.json \
  https://CVM_HOST/evidence > capture-dir/evidence-response.json

cargo run -p binary-attestation-dstack --example live_core_verifier -- \
  verify capture-dir/snapshot.json capture-dir/challenge.json \
  capture-dir/evidence-response.json
```

The challenge expires after three minutes. Issue it only after the CVM is
healthy and the policy file is complete. Delete the disposable CVM after the
sanitized public evidence and exact digests are retained.
