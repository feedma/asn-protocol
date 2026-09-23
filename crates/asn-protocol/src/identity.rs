//! P-256 JWS ES256 composition and verification for ASN identities.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::Verifier as _},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{canonical::canonicalize, signers::JwsSigner};

pub use crate::signers::SignerError;

const JWS_ALGORITHM: &str = "ES256";
const JWS_TYPE: &str = "asn-worker+jws";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    pub key_id: String,
    pub jwk: PublicJwk,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedJws {
    pub compact: String,
    pub key_id: String,
    pub canonical_payload: Vec<u8>,
    pub payload: Value,
}

#[derive(Debug, Error)]
pub enum JwsError {
    #[error("JWS compact serialization must contain three non-empty segments")]
    MalformedCompact,
    #[error("JWS segment is not unpadded base64url")]
    InvalidBase64,
    #[error("protected JWS header is invalid: {0}")]
    InvalidHeader(String),
    #[error("JWS payload is not canonical JCS: {0}")]
    NonCanonicalPayload(String),
    #[error("JWS key identifier is unknown or inactive")]
    UnknownKey,
    #[error("public key is not a P-256 EC JWK")]
    InvalidKey,
    #[error("ES256 signature is invalid")]
    InvalidSignature,
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error("payload cannot be represented as JCS: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: String,
}

pub fn build_compact_jws<T>(payload: &T, signer: &dyn JwsSigner) -> Result<String, JwsError>
where
    T: Serialize,
{
    let header = ProtectedHeader {
        alg: JWS_ALGORITHM.into(),
        kid: signer.key_id().into(),
        typ: JWS_TYPE.into(),
    };
    let protected = URL_SAFE_NO_PAD.encode(serde_jcs::to_vec(&header)?);
    let payload = URL_SAFE_NO_PAD.encode(serde_jcs::to_vec(payload)?);
    let signing_input = format!("{protected}.{payload}");
    let signature = signer.sign_es256(signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

pub fn verify_compact_jws(
    compact: &str,
    expected_key: &VerificationKey,
) -> Result<VerifiedJws, JwsError> {
    let segments: Vec<_> = compact.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(JwsError::MalformedCompact);
    }

    let protected_bytes = decode_segment(segments[0])?;
    let protected_canonical = canonicalize(&protected_bytes)
        .map_err(|error| JwsError::InvalidHeader(error.to_string()))?;
    let header: ProtectedHeader = serde_json::from_slice(&protected_canonical)
        .map_err(|error| JwsError::InvalidHeader(error.to_string()))?;
    if header.alg != JWS_ALGORITHM || header.typ != JWS_TYPE {
        return Err(JwsError::InvalidHeader(
            "required alg or typ does not match the ASN profile".into(),
        ));
    }
    if header.kid != expected_key.key_id {
        return Err(JwsError::UnknownKey);
    }

    let payload_bytes = decode_segment(segments[1])?;
    let canonical = canonicalize(&payload_bytes)
        .map_err(|error| JwsError::NonCanonicalPayload(error.to_string()))?;
    if canonical != payload_bytes {
        return Err(JwsError::NonCanonicalPayload(
            "received bytes differ from their RFC 8785 form".into(),
        ));
    }

    let signature_bytes = decode_segment(segments[2])?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| JwsError::InvalidSignature)?;
    let verifying_key = verifying_key(&expected_key.jwk)?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| JwsError::InvalidSignature)?;

    let payload = serde_json::from_slice(&payload_bytes)?;
    Ok(VerifiedJws {
        compact: compact.into(),
        key_id: header.kid,
        canonical_payload: payload_bytes,
        payload,
    })
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, JwsError> {
    if segment.contains('=') {
        return Err(JwsError::InvalidBase64);
    }
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| JwsError::InvalidBase64)
}

fn verifying_key(jwk: &PublicJwk) -> Result<VerifyingKey, JwsError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(JwsError::InvalidKey);
    }
    let x = decode_coordinate(&jwk.x)?;
    let y = decode_coordinate(&jwk.y)?;
    let point = EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
    VerifyingKey::from_encoded_point(&point).map_err(|_| JwsError::InvalidKey)
}

fn decode_coordinate(encoded: &str) -> Result<[u8; 32], JwsError> {
    let decoded = decode_segment(encoded).map_err(|_| JwsError::InvalidKey)?;
    decoded.try_into().map_err(|_| JwsError::InvalidKey)
}
