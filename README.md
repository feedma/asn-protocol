# ASN Protocol

Executable, transport-neutral contracts for the Agent Service Network. The
initial `0.1.0-alpha.1` release provides:

- RFC 8785 JSON canonicalization with rejection of ambiguous input;
- version `1` worker envelopes with preserved extension fields;
- P-256/JWS `ES256` composition and verification for `did:web` key IDs;
- separate seams for ASN JWS, EIP-712, credential-holder and data-key signers;
- language-neutral schemas and reusable valid/invalid conformance vectors.

The `0.2.0-alpha.1` release adds provider-defined, versioned service
contracts with inline JSON Schemas, RFC 8785/SHA-256 contract bindings and
worker support assertions that reference an exact contract hash.

The `0.3.0-alpha.1` release adds transport-neutral worker control
contracts for:

- challenge-bound worker enrollment and provider-signed delegation;
- proof-of-possession bound to provider, worker key, exact service scope,
  environment, audience and expiry;
- authenticated session challenges with durable bidirectional cursors;
- exact service capabilities and concurrent-operation slot reports; and
- provider-authorized revocation leases with a five-minute maximum freshness
  window.

The Rust types enforce cross-object bindings and time windows. The
[`worker-control-v1` schema](schemas/worker-control-v1.schema.json) and shared
positive/negative fixtures keep non-Rust implementations aligned without
making WebSocket framing part of the authorization contract.

The next `0.3.0-alpha.2` release adds the missing provider-to-revocation-
authority delegation. Status authorities can issue short-lived worker leases
only for the bound provider, worker DID, worker delegation, revocation identity
and environment. The worker lease now carries those authority-chain bindings,
so gateway connectivity alone cannot manufacture fresh authorization state.

Run every check from the repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p asn-conformance --quiet
```

The conformance runner accepts an alternate vector file as its first argument.
The default is [`fixtures/conformance-v1.json`](fixtures/conformance-v1.json).

## Compatibility

Every envelope declares its protocol major as a canonical decimal string.
This release accepts only `"1"` and reports other majors as unsupported. New
optional fields are preserved in the envelope extension map. A peer must reject
an unsupported major explicitly.

Crate releases follow SemVer. Consumers should pin a released version and its
resolved commit or lockfile. The release workflow accepts only signed annotated
tags and publishes the `asn-protocol` crate plus provenance for its package.
