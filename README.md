# ASN Protocol

Executable, transport-neutral contracts for the Agent Service Network. The
initial `0.1.0-alpha.1` release provides:

- RFC 8785 JSON canonicalization with rejection of ambiguous input;
- version `1` worker envelopes with preserved extension fields;
- P-256/JWS `ES256` composition and verification for `did:web` key IDs;
- separate seams for ASN JWS, EIP-712, credential-holder and data-key signers;
- language-neutral schemas and reusable valid/invalid conformance vectors.

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
tags and publishes the crate and GitHub release from the exact tagged revision.
