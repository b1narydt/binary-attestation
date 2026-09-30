# AGENTS.md — binary-attestation

This repository implements Binary Confidential Attestation Protocol v1
(BCAP1). Project work is tracked in
`project-at-las/Atlas-Documentation`; its `AGENTS.md` workflow governs issue,
review, evidence, and push handling.

## Boundaries

- `spec/` and `vectors/` are the cross-language contract. Rust and TypeScript
  consume the same checked-in artifacts.
- `typescript/` is browser-safe. Native sockets, DCAP, NVML/NVAT, verifier
  services, key brokers, Atlas Relay, and MPC dependencies do not belong in
  its dependency graph.
- `rust/core/` is provider-neutral. Provider runtimes live in separate crates.
- Atlas is an optional authenticated carrier and never an attestation trust
  root. No Atlas Relay challenge, verifier, verdict, or admission state belongs
  here.
- A protocol field, transcript byte, or denial-semantic change requires new
  versioned vectors; never mutate a released vector in place.

## Required baseline

Run `bash scripts/baseline.sh`. It checks immutable vectors, TypeScript and
Rust formatting/lint/tests, browser dependency boundaries, and documentation.

