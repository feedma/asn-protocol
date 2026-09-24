//! Provider-defined service contracts and worker support bindings.

use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::canonical::canonicalize;

pub const SERVICE_CONTRACT_VERSION: &str = "1";
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceContract {
    pub contract_version: String,
    pub service_id: String,
    pub service_version: String,
    pub name: String,
    pub description: String,
    pub operations: Vec<OperationContract>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationContract {
    pub id: String,
    pub description: String,
    pub execution_modes: Vec<String>,
    pub input: DataContract,
    pub output: DataContract,
    #[serde(default)]
    pub authorization_protocols: Vec<String>,
    #[serde(default)]
    pub payment_protocols: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataContract {
    /// JSON Schema represented as an inline JSON object or boolean schema.
    pub schema: Value,
    pub media_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerServiceSupport {
    pub service_id: String,
    pub service_version: String,
    pub contract_hash: String,
}

#[derive(Debug, Error)]
pub enum ServiceContractError {
    #[error("service contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("service contract is invalid: {0}")]
    Invalid(&'static str),
}

impl ServiceContract {
    /// Parse an unambiguous JSON contract and validate its protocol invariants.
    pub fn from_slice(input: &[u8]) -> Result<Self, ServiceContractError> {
        let canonical = canonicalize(input)
            .map_err(|error| ServiceContractError::InvalidJson(error.to_string()))?;
        let contract: Self = serde_json::from_slice(&canonical)
            .map_err(|error| ServiceContractError::InvalidJson(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), ServiceContractError> {
        if self.contract_version != SERVICE_CONTRACT_VERSION {
            return Err(ServiceContractError::Invalid("unsupported contractVersion"));
        }
        if !valid_identifier(&self.service_id, 128, b"-._/") {
            return Err(ServiceContractError::Invalid("invalid serviceId"));
        }
        if !valid_version(&self.service_version) {
            return Err(ServiceContractError::Invalid("invalid serviceVersion"));
        }
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err(ServiceContractError::Invalid("invalid service name"));
        }
        if self.description.trim().is_empty() || self.description.len() > 2_048 {
            return Err(ServiceContractError::Invalid("invalid service description"));
        }
        if self.operations.is_empty() || self.operations.len() > 64 {
            return Err(ServiceContractError::Invalid(
                "operations must contain between 1 and 64 entries",
            ));
        }
        let mut operation_ids = HashSet::with_capacity(self.operations.len());
        for operation in &self.operations {
            operation.validate()?;
            if !operation_ids.insert(&operation.id) {
                return Err(ServiceContractError::Invalid("duplicate operation id"));
            }
        }
        Ok(())
    }

    /// Return the RFC 8785 SHA-256 binding used by workers, mandates and payments.
    pub fn contract_hash(&self) -> Result<String, ServiceContractError> {
        self.validate()?;
        let canonical = serde_jcs::to_vec(self)
            .map_err(|error| ServiceContractError::InvalidJson(error.to_string()))?;
        Ok(format!(
            "urn:sha256:{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
        ))
    }
}

impl OperationContract {
    fn validate(&self) -> Result<(), ServiceContractError> {
        if !valid_identifier(&self.id, 128, b"-._/") {
            return Err(ServiceContractError::Invalid("invalid operation id"));
        }
        if self.description.trim().is_empty() || self.description.len() > 2_048 {
            return Err(ServiceContractError::Invalid(
                "invalid operation description",
            ));
        }
        validate_identifiers(&self.execution_modes, "invalid executionModes")?;
        validate_optional_identifiers(
            &self.authorization_protocols,
            "invalid authorizationProtocols",
        )?;
        validate_optional_identifiers(&self.payment_protocols, "invalid paymentProtocols")?;
        self.input.validate()?;
        self.output.validate()?;
        Ok(())
    }
}

impl DataContract {
    fn validate(&self) -> Result<(), ServiceContractError> {
        if !self.schema.is_object() && !self.schema.is_boolean() {
            return Err(ServiceContractError::Invalid(
                "schema must be a JSON object or boolean",
            ));
        }
        if self.media_types.is_empty() || self.media_types.len() > 32 {
            return Err(ServiceContractError::Invalid(
                "mediaTypes must contain between 1 and 32 entries",
            ));
        }
        let mut media_types = HashSet::with_capacity(self.media_types.len());
        for media_type in &self.media_types {
            if media_type.is_empty()
                || media_type.len() > 127
                || !media_type.is_ascii()
                || media_type.bytes().any(|byte| byte.is_ascii_whitespace())
                || media_type.matches('/').count() != 1
                || media_type.starts_with('/')
                || media_type.ends_with('/')
                || !media_types.insert(media_type)
            {
                return Err(ServiceContractError::Invalid("invalid mediaTypes"));
            }
        }
        if self
            .max_bytes
            .is_some_and(|value| value == 0 || value > MAX_SAFE_JSON_INTEGER)
        {
            return Err(ServiceContractError::Invalid("invalid maxBytes"));
        }
        Ok(())
    }
}

impl WorkerServiceSupport {
    pub fn validate(&self) -> Result<(), ServiceContractError> {
        if !valid_identifier(&self.service_id, 128, b"-._/") {
            return Err(ServiceContractError::Invalid("invalid serviceId"));
        }
        if !valid_version(&self.service_version) {
            return Err(ServiceContractError::Invalid("invalid serviceVersion"));
        }
        if !valid_contract_hash(&self.contract_hash) {
            return Err(ServiceContractError::Invalid("invalid contractHash"));
        }
        Ok(())
    }
}

fn validate_identifiers(
    values: &[String],
    error: &'static str,
) -> Result<(), ServiceContractError> {
    if values.is_empty() || values.len() > 32 {
        return Err(ServiceContractError::Invalid(error));
    }
    let mut unique = HashSet::with_capacity(values.len());
    if values
        .iter()
        .any(|value| !valid_identifier(value, 64, b"-._/") || !unique.insert(value))
    {
        return Err(ServiceContractError::Invalid(error));
    }
    Ok(())
}

fn validate_optional_identifiers(
    values: &[String],
    error: &'static str,
) -> Result<(), ServiceContractError> {
    if values.is_empty() {
        return Ok(());
    }
    validate_identifiers(values, error)
}

fn valid_identifier(value: &str, max_len: usize, punctuation: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || punctuation.contains(&byte)
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

fn valid_contract_hash(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("urn:sha256:") else {
        return false;
    };
    encoded.len() == 43
        && !encoded.contains('=')
        && URL_SAFE_NO_PAD
            .decode(encoded)
            .is_ok_and(|digest| digest.len() == 32)
}
