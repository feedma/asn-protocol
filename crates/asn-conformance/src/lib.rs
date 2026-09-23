use std::{error::Error, fs, path::Path};

use asn_protocol::{
    canonical::canonicalize,
    identity::{PublicJwk, VerificationKey, verify_compact_jws},
    wire::Envelope,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Vectors {
    version: String,
    canonicalization: Vec<CanonicalizationVector>,
    envelopes: Vec<EnvelopeVector>,
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
