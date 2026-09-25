use std::{error::Error, fs, path::Path};

use asn_protocol::{
    canonical::canonicalize,
    identity::{PublicJwk, VerificationKey, verify_compact_jws},
    service::ServiceContract,
    wire::Envelope,
    worker::{
        RevocationAuthorityDelegation, WorkerCapabilities, WorkerDelegation, WorkerEnrollmentProof,
        WorkerRevocationLease, WorkerScope, WorkerSessionProof,
    },
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Vectors {
    version: String,
    canonicalization: Vec<CanonicalizationVector>,
    envelopes: Vec<EnvelopeVector>,
    service_contracts: Vec<ServiceContractVector>,
    worker_contracts: Vec<WorkerContractVector>,
    jws: Vec<JwsVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalizationVector {
    name: String,
    input: String,
    valid: bool,
    canonical: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JwsVector {
    name: String,
    compact: String,
    key_id: String,
    public_key_jwk: PublicJwk,
    key_active: bool,
    expected_thumbprint: String,
    valid: bool,
    payload: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnvelopeVector {
    name: String,
    input: String,
    valid: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceContractVector {
    name: String,
    input: String,
    valid: bool,
    contract_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerContractVector {
    name: String,
    contract_type: String,
    input: String,
    valid: bool,
    canonical_hash: Option<String>,
}

pub fn run_file(path: impl AsRef<Path>) -> Result<usize, Box<dyn Error>> {
    let vectors: Vectors = serde_json::from_slice(&fs::read(path)?)?;
    if vectors.version != "1" {
        return Err(format!("unsupported vector version {}", vectors.version).into());
    }

    let mut checked = 0;
    for vector in vectors.canonicalization {
        let result = canonicalize(vector.input.as_bytes());
        match (vector.valid, result, vector.canonical) {
            (true, Ok(actual), Some(expected)) if actual == expected.as_bytes() => {}
            (false, Err(_), None) => {}
            _ => return Err(format!("canonicalization vector failed: {}", vector.name).into()),
        }
        checked += 1;
    }

    for vector in vectors.envelopes {
        let result = Envelope::from_slice(vector.input.as_bytes());
        if result.is_ok() != vector.valid {
            return Err(format!("envelope vector failed: {}", vector.name).into());
        }
        checked += 1;
    }

    for vector in vectors.service_contracts {
        let result = ServiceContract::from_slice(vector.input.as_bytes())
            .and_then(|contract| contract.contract_hash());
        match (vector.valid, result, vector.contract_hash) {
            (true, Ok(actual), Some(expected)) if actual == expected => {}
            (false, Err(_), None) => {}
            _ => {
                return Err(format!("service contract vector failed: {}", vector.name).into());
            }
        }
        checked += 1;
    }

    for vector in vectors.worker_contracts {
        let result = validate_worker_contract(&vector.contract_type, vector.input.as_bytes());
        match (vector.valid, result, vector.canonical_hash) {
            (true, Ok(actual), expected) if actual == expected => {}
            (false, Err(_), None) => {}
            _ => return Err(format!("worker contract vector failed: {}", vector.name).into()),
        }
        checked += 1;
    }

    for vector in vectors.jws {
        let key = VerificationKey {
            key_id: vector.key_id,
            jwk: vector.public_key_jwk,
            active: vector.key_active,
        };
        if key.jwk.thumbprint()? != vector.expected_thumbprint {
            return Err(format!("JWS thumbprint failed: {}", vector.name).into());
        }
        let result = verify_compact_jws(&vector.compact, &key);
        match (vector.valid, result, vector.payload) {
            (true, Ok(actual), Some(expected)) if actual.payload == expected => {}
            (false, Err(_), None) => {}
            _ => return Err(format!("JWS vector failed: {}", vector.name).into()),
        }
        checked += 1;
    }

    Ok(checked)
}

fn validate_worker_contract(
    contract_type: &str,
    input: &[u8],
) -> Result<Option<String>, Box<dyn Error>> {
    let canonical = canonicalize(input)?;
    match contract_type {
        "WorkerScope" => {
            let value: WorkerScope = serde_json::from_slice(&canonical)?;
            Ok(Some(value.hash()?))
        }
        "WorkerEnrollmentProof" => {
            let value: WorkerEnrollmentProof = serde_json::from_slice(&canonical)?;
            value.validate()?;
            Ok(None)
        }
        "WorkerDelegation" => {
            let value: WorkerDelegation = serde_json::from_slice(&canonical)?;
            value.validate()?;
            Ok(None)
        }
        "RevocationAuthorityDelegation" => {
            let value: RevocationAuthorityDelegation = serde_json::from_slice(&canonical)?;
            value.validate()?;
            Ok(None)
        }
        "WorkerSessionProof" => {
            let value: WorkerSessionProof = serde_json::from_slice(&canonical)?;
            value.validate()?;
            Ok(None)
        }
        "WorkerCapabilities" => {
            let value: WorkerCapabilities = serde_json::from_slice(&canonical)?;
            value.validate()?;
            Ok(None)
        }
        "WorkerRevocationLease" => {
            let value: WorkerRevocationLease = serde_json::from_slice(&canonical)?;
            value.validate()?;
            Ok(None)
        }
        _ => Err(format!("unknown worker contract type {contract_type}").into()),
    }
}
