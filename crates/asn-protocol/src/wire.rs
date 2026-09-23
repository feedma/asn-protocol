//! Versioned envelopes shared by transport adapters.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::canonical::canonicalize;

pub const SUPPORTED_PROTOCOL_MAJOR: u64 = 1;
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub version: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub message_id: String,
    pub sequence: u64,
    pub sent_at: String,
    pub correlation_id: Option<String>,
    pub body: Value,
    pub proof: Option<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("envelope is not unambiguous JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol version must be a canonical unsigned major version")]
    MalformedVersion,
    #[error("unsupported protocol major version {0}")]
    UnsupportedMajor(u64),
    #[error("envelope sequence exceeds the interoperable JSON integer range")]
    InvalidSequence,
}

impl PartialEq for EnvelopeError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MalformedVersion, Self::MalformedVersion) => true,
            (Self::UnsupportedMajor(left), Self::UnsupportedMajor(right)) => left == right,
            (Self::InvalidSequence, Self::InvalidSequence) => true,
            (Self::Json(_), Self::Json(_)) => true,
            _ => false,
        }
    }
}

impl Envelope {
    pub fn from_slice(input: &[u8]) -> Result<Self, EnvelopeError> {
        // Canonicalization first rejects duplicate member names at every depth.
        let canonical = canonicalize(input)?;
        let envelope: Self = serde_json::from_slice(&canonical)?;
        let major = parse_major(&envelope.version)?;
        if major != SUPPORTED_PROTOCOL_MAJOR {
            return Err(EnvelopeError::UnsupportedMajor(major));
        }
        if envelope.sequence > MAX_SAFE_JSON_INTEGER {
            return Err(EnvelopeError::InvalidSequence);
        }
        Ok(envelope)
    }

    pub fn to_canonical_vec(&self) -> Result<Vec<u8>, EnvelopeError> {
        parse_major(&self.version)?;
        if self.sequence > MAX_SAFE_JSON_INTEGER {
            return Err(EnvelopeError::InvalidSequence);
        }
        Ok(serde_jcs::to_vec(self)?)
    }
}

fn parse_major(version: &str) -> Result<u64, EnvelopeError> {
    if version.is_empty()
        || (version.len() > 1 && version.starts_with('0'))
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EnvelopeError::MalformedVersion);
    }
    version.parse().map_err(|_| EnvelopeError::MalformedVersion)
}
