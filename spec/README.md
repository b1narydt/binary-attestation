# BCAP1 contract provenance

These schemas and the sibling `vectors/` directory implement the initial
BCAP1 A0/A1 contract accepted by Atlas ADR-039.

Normative prose source:

- repository: `project-at-las/Atlas-Documentation`
- commit: `15f783cc9337fd4bab2d3ba66c16a1a124e89220`
- path: `flagship/specs/confidential-attestation-protocol.md`
- git blob: `4172d522c39de0828163967815594997a79ac88b`
- SHA-256: `9f252118cd60394c262c852dafc659ad423b19f97135235a58ba554c813dc333`

The checked-in vectors, rather than prose examples, lock transcript and wire
bytes. Released vector files are immutable. Any incompatible field, encoding,
digest, or denial-semantics change requires a new protocol/vector version.

Provider profiles, authenticated channel implementations, signed leases, and
application adapters land behind later gates. The A0/A1 core contains their
interfaces and provider-neutral validation only.
