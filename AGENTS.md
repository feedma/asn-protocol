# ASN protocol project

This repository owns transport-neutral ASN wire contracts, canonicalization,
identity verification, signer interfaces, schemas, fixtures and conformance.
Keep application persistence, orchestration and transport framework types in
their owning repositories.

Use English for code and documentation. Add behavior through public-interface
conformance tests and keep fixtures usable without application code. Run
`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` and `cargo run -p asn-conformance --quiet` before a PR.

Protocol crates follow SemVer. Breaking wire behavior increments major;
backward-compatible optional additions increment minor; corrections without
observable wire changes increment patch. Releases require an annotated signed
`v<semver>` tag and the release workflow.
