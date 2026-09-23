#[test]
fn released_vectors_pass_without_application_code() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/conformance-v1.json"
    );
    assert_eq!(asn_conformance::run_file(path).unwrap(), 8);
}
