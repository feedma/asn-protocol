use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let path = env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance-v1.json")
    });
    match asn_conformance::run_file(&path) {
        Ok(count) => {
            println!("ASN protocol conformance: {count} vectors passed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ASN protocol conformance failed: {error}");
            ExitCode::FAILURE
        }
    }
}
