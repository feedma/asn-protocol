//! Transport-neutral worker enrollment, delegation, session and capability contracts.

use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{identity::PublicJwk, service::WorkerServiceSupport, wire::MAX_SAFE_JSON_INTEGER};

pub const WORKER_CONTRACT_VERSION: &str = "1";
pub const DEFAULT_MAX_REVOCATION_STALENESS_SECONDS: u64 = 300;
pub const MAX_ENROLLMENT_CHALLENGE_SECONDS: i64 = 300;
pub const MAX_SESSION_CHALLENGE_SECONDS: i64 = 60;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerScope {
    pub services: Vec<WorkerServiceSupport>,
    pub max_concurrent_operations: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateWorkerEnrollmentChallenge {
    pub provider_id: String,
    pub worker_did: String,
    pub public_key_jwk: PublicJwk,
    pub key_id: String,
    pub requested_scope: WorkerScope,
    pub environment: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerEnrollmentChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub audience: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerEnrollmentProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub version: String,
    pub challenge_id: String,
    pub nonce: String,
    pub provider_id: String,
    pub worker_did: String,
    pub key_id: String,
    pub public_key_thumbprint: String,
    pub requested_scope_hash: String,
    pub environment: String,
    pub audience: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerDelegation {
    #[serde(rename = "type")]
    pub delegation_type: String,
    pub version: String,
    pub delegation_id: String,
    pub provider_id: String,
    pub worker_did: String,
    pub key_id: String,
    pub public_key_thumbprint: String,
    pub scope: WorkerScope,
    pub environment: String,
    pub protocol_version: String,
    pub not_before: String,
    pub expires_at: String,
    pub revocation_id: String,
    pub max_revocation_staleness_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompleteWorkerEnrollment {
    pub worker_proof_jws: String,
    pub provider_delegation_jws: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerEnrollment {
    pub worker_id: String,
    pub effective_scope: WorkerScope,
    pub credential: String,
    pub gateway_url: String,
    pub protocol_versions: Vec<String>,
    pub revocation_lease_jws: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableCursors {
    pub worker_to_gateway: u64,
    pub gateway_to_worker: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionHello {
    pub worker_id: String,
    pub credential: String,
    pub supported_protocol_versions: Vec<String>,
    pub cursors: DurableCursors,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionChallenge {
    pub session_id: String,
    pub nonce: String,
    pub audience: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerSessionProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub version: String,
    pub session_id: String,
    pub nonce: String,
    pub worker_id: String,
    pub environment: String,
    pub audience: String,
    pub cursors: DurableCursors,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionReady {
    pub session_id: String,
    pub negotiated_protocol_version: String,
    pub authoritative_cursors: DurableCursors,
    pub heartbeat_interval_seconds: u64,
    pub revocation_lease_jws: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerCapacity {
    pub max_concurrent_operations: u64,
    pub active_operations: u64,
    pub reserved_operations: u64,
    pub available_operation_slots: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerCapabilities {
    pub services: Vec<WorkerServiceSupport>,
    pub capacity: WorkerCapacity,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerRevocationLease {
    #[serde(rename = "type")]
    pub lease_type: String,
    pub version: String,
    pub issuer: String,
    pub provider_id: String,
    pub worker_id: String,
    pub delegation_id: String,
    pub revocation_id: String,
    pub environment: String,
    pub status: RevocationStatus,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WorkerContractError {
    #[error("worker contract is invalid: {0}")]
    Invalid(&'static str),
    #[error("worker contract timestamp is invalid: {0}")]
    InvalidTimestamp(&'static str),
    #[error("worker contract time window is invalid: {0}")]
    InvalidTimeWindow(&'static str),
    #[error("worker contract binding does not match: {0}")]
    BindingMismatch(&'static str),
    #[error("worker scope serialization failed: {0}")]
    Serialization(String),
}

impl WorkerScope {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        if self.services.is_empty() || self.services.len() > 256 {
            return Err(WorkerContractError::Invalid("invalid services"));
        }
        if self.max_concurrent_operations == 0
            || self.max_concurrent_operations > MAX_SAFE_JSON_INTEGER
        {
            return Err(WorkerContractError::Invalid(
                "invalid maxConcurrentOperations",
            ));
        }
        let mut services = HashSet::with_capacity(self.services.len());
        for service in &self.services {
            service
                .validate()
                .map_err(|_| WorkerContractError::Invalid("invalid service support"))?;
            if !services.insert((
                service.service_id.as_str(),
                service.service_version.as_str(),
                service.contract_hash.as_str(),
            )) {
                return Err(WorkerContractError::Invalid("duplicate service support"));
            }
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<String, WorkerContractError> {
        self.validate()?;
        let canonical = serde_jcs::to_vec(self)
            .map_err(|error| WorkerContractError::Serialization(error.to_string()))?;
        Ok(format!(
            "urn:sha256:{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
        ))
    }

    pub fn is_within(&self, authorized: &Self) -> bool {
        if self.validate().is_err()
            || authorized.validate().is_err()
            || self.max_concurrent_operations > authorized.max_concurrent_operations
        {
            return false;
        }
        self.services.iter().all(|requested| {
            authorized
                .services
                .iter()
                .any(|allowed| allowed == requested)
        })
    }
}

impl CreateWorkerEnrollmentChallenge {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_did(&self.provider_id, "invalid providerId")?;
        validate_worker_key(&self.worker_did, &self.key_id)?;
        self.public_key_jwk
            .thumbprint()
            .map_err(|_| WorkerContractError::Invalid("invalid publicKeyJwk"))?;
        self.requested_scope.validate()?;
        validate_token(&self.environment, "invalid environment")
    }
}

impl WorkerEnrollmentChallenge {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_token(&self.challenge_id, "invalid challengeId")?;
        validate_nonce(&self.nonce)?;
        validate_audience(&self.audience)?;
        parse_timestamp(&self.expires_at, "enrollment challenge")?;
        Ok(())
    }

    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), WorkerContractError> {
        self.validate()?;
        let expires_at = parse_timestamp(&self.expires_at, "enrollment challenge")?;
        if now > expires_at {
            return Err(WorkerContractError::InvalidTimeWindow(
                "expired enrollment challenge",
            ));
        }
        if (expires_at - now).whole_seconds() > MAX_ENROLLMENT_CHALLENGE_SECONDS {
            return Err(WorkerContractError::InvalidTimeWindow(
                "enrollment challenge exceeds maximum lifetime",
            ));
        }
        Ok(())
    }
}

impl WorkerEnrollmentProof {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_type_version(&self.proof_type, "WorkerEnrollmentProof", &self.version)?;
        validate_token(&self.challenge_id, "invalid challengeId")?;
        validate_nonce(&self.nonce)?;
        validate_did(&self.provider_id, "invalid providerId")?;
        validate_worker_key(&self.worker_did, &self.key_id)?;
        validate_digest(&self.public_key_thumbprint, "invalid publicKeyThumbprint")?;
        validate_hash(&self.requested_scope_hash, "invalid requestedScopeHash")?;
        validate_token(&self.environment, "invalid environment")?;
        validate_audience(&self.audience)?;
        validate_window(
            &self.issued_at,
            &self.expires_at,
            MAX_ENROLLMENT_CHALLENGE_SECONDS,
            "enrollment proof",
        )
    }

    pub fn validate_for(
        &self,
        request: &CreateWorkerEnrollmentChallenge,
        challenge: &WorkerEnrollmentChallenge,
        now: OffsetDateTime,
    ) -> Result<(), WorkerContractError> {
        self.validate()?;
        request.validate()?;
        challenge.validate_at(now)?;
        if self.challenge_id != challenge.challenge_id
            || self.nonce != challenge.nonce
            || self.audience != challenge.audience
        {
            return Err(WorkerContractError::BindingMismatch("challenge"));
        }
        if self.provider_id != request.provider_id
            || self.worker_did != request.worker_did
            || self.key_id != request.key_id
            || self.environment != request.environment
        {
            return Err(WorkerContractError::BindingMismatch("enrollment request"));
        }
        if self.public_key_thumbprint
            != request
                .public_key_jwk
                .thumbprint()
                .map_err(|_| WorkerContractError::Invalid("invalid publicKeyJwk"))?
            || self.requested_scope_hash != request.requested_scope.hash()?
        {
            return Err(WorkerContractError::BindingMismatch(
                "enrollment key or scope",
            ));
        }
        let issued_at = parse_timestamp(&self.issued_at, "enrollment proof")?;
        let expires_at = parse_timestamp(&self.expires_at, "enrollment proof")?;
        if expires_at > parse_timestamp(&challenge.expires_at, "enrollment challenge")?
            || issued_at > now
            || now > expires_at
        {
            return Err(WorkerContractError::InvalidTimeWindow(
                "enrollment proof outside challenge",
            ));
        }
        Ok(())
    }
}

impl WorkerDelegation {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_type_version(&self.delegation_type, "WorkerDelegation", &self.version)?;
        validate_token(&self.delegation_id, "invalid delegationId")?;
        validate_did(&self.provider_id, "invalid providerId")?;
        validate_worker_key(&self.worker_did, &self.key_id)?;
        validate_digest(&self.public_key_thumbprint, "invalid publicKeyThumbprint")?;
        self.scope.validate()?;
        validate_token(&self.environment, "invalid environment")?;
        if self.protocol_version != "1" {
            return Err(WorkerContractError::Invalid("unsupported protocolVersion"));
        }
        validate_window(
            &self.not_before,
            &self.expires_at,
            i64::MAX,
            "worker delegation",
        )?;
        validate_token(&self.revocation_id, "invalid revocationId")?;
        if self.max_revocation_staleness_seconds == 0
            || self.max_revocation_staleness_seconds > DEFAULT_MAX_REVOCATION_STALENESS_SECONDS
        {
            return Err(WorkerContractError::Invalid(
                "invalid maxRevocationStalenessSeconds",
            ));
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        request: &CreateWorkerEnrollmentChallenge,
        now: OffsetDateTime,
    ) -> Result<(), WorkerContractError> {
        self.validate()?;
        request.validate()?;
        if self.provider_id != request.provider_id
            || self.worker_did != request.worker_did
            || self.key_id != request.key_id
            || self.environment != request.environment
            || self.public_key_thumbprint
                != request
                    .public_key_jwk
                    .thumbprint()
                    .map_err(|_| WorkerContractError::Invalid("invalid publicKeyJwk"))?
        {
            return Err(WorkerContractError::BindingMismatch("worker delegation"));
        }
        if !request.requested_scope.is_within(&self.scope) {
            return Err(WorkerContractError::BindingMismatch("delegated scope"));
        }
        if now < parse_timestamp(&self.not_before, "worker delegation")?
            || now > parse_timestamp(&self.expires_at, "worker delegation")?
        {
            return Err(WorkerContractError::InvalidTimeWindow(
                "inactive worker delegation",
            ));
        }
        Ok(())
    }
}

impl CompleteWorkerEnrollment {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_compact_jws(&self.worker_proof_jws, "invalid workerProofJws")?;
        validate_compact_jws(
            &self.provider_delegation_jws,
            "invalid providerDelegationJws",
        )
    }
}

impl WorkerEnrollment {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_token(&self.worker_id, "invalid workerId")?;
        self.effective_scope.validate()?;
        validate_token(&self.credential, "invalid credential")?;
        if !self.gateway_url.starts_with("wss://")
            || self.gateway_url.len() <= 6
            || self.gateway_url.len() > 2_048
            || self
                .gateway_url
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            return Err(WorkerContractError::Invalid("invalid gatewayUrl"));
        }
        validate_protocol_versions(&self.protocol_versions)?;
        validate_compact_jws(&self.revocation_lease_jws, "invalid revocationLeaseJws")
    }
}

impl DurableCursors {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        if self.worker_to_gateway > MAX_SAFE_JSON_INTEGER
            || self.gateway_to_worker > MAX_SAFE_JSON_INTEGER
        {
            return Err(WorkerContractError::Invalid("invalid durable cursor"));
        }
        Ok(())
    }
}

impl WorkerSessionProof {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_type_version(&self.proof_type, "WorkerSessionProof", &self.version)?;
        validate_token(&self.session_id, "invalid sessionId")?;
        validate_nonce(&self.nonce)?;
        validate_token(&self.worker_id, "invalid workerId")?;
        validate_token(&self.environment, "invalid environment")?;
        validate_audience(&self.audience)?;
        self.cursors.validate()?;
        validate_window(
            &self.issued_at,
            &self.expires_at,
            MAX_SESSION_CHALLENGE_SECONDS,
            "session proof",
        )
    }

    pub fn validate_for(
        &self,
        hello: &SessionHello,
        challenge: &SessionChallenge,
        environment: &str,
        now: OffsetDateTime,
    ) -> Result<(), WorkerContractError> {
        self.validate()?;
        hello.validate()?;
        challenge.validate_at(now)?;
        if self.session_id != challenge.session_id
            || self.nonce != challenge.nonce
            || self.audience != challenge.audience
            || self.worker_id != hello.worker_id
            || self.cursors != hello.cursors
            || self.environment != environment
        {
            return Err(WorkerContractError::BindingMismatch("worker session"));
        }
        let issued_at = parse_timestamp(&self.issued_at, "session proof")?;
        let expires_at = parse_timestamp(&self.expires_at, "session proof")?;
        if expires_at > parse_timestamp(&challenge.expires_at, "session challenge")?
            || issued_at > now
            || now > expires_at
        {
            return Err(WorkerContractError::InvalidTimeWindow(
                "session proof outside challenge",
            ));
        }
        Ok(())
    }
}

impl SessionHello {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_token(&self.worker_id, "invalid workerId")?;
        validate_token(&self.credential, "invalid credential")?;
        validate_protocol_versions(&self.supported_protocol_versions)?;
        self.cursors.validate()
    }
}

impl SessionChallenge {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_token(&self.session_id, "invalid sessionId")?;
        validate_nonce(&self.nonce)?;
        validate_audience(&self.audience)?;
        parse_timestamp(&self.expires_at, "session challenge")?;
        Ok(())
    }

    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), WorkerContractError> {
        self.validate()?;
        let expires_at = parse_timestamp(&self.expires_at, "session challenge")?;
        if now > expires_at {
            return Err(WorkerContractError::InvalidTimeWindow(
                "expired session challenge",
            ));
        }
        if (expires_at - now).whole_seconds() > MAX_SESSION_CHALLENGE_SECONDS {
            return Err(WorkerContractError::InvalidTimeWindow(
                "session challenge exceeds maximum lifetime",
            ));
        }
        Ok(())
    }
}

impl SessionReady {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_token(&self.session_id, "invalid sessionId")?;
        if self.negotiated_protocol_version != "1" {
            return Err(WorkerContractError::Invalid(
                "unsupported negotiatedProtocolVersion",
            ));
        }
        self.authoritative_cursors.validate()?;
        if self.heartbeat_interval_seconds == 0
            || self.heartbeat_interval_seconds > MAX_SAFE_JSON_INTEGER
        {
            return Err(WorkerContractError::Invalid(
                "invalid heartbeatIntervalSeconds",
            ));
        }
        validate_compact_jws(&self.revocation_lease_jws, "invalid revocationLeaseJws")
    }
}

impl WorkerCapacity {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        let values = [
            self.max_concurrent_operations,
            self.active_operations,
            self.reserved_operations,
            self.available_operation_slots,
        ];
        if self.max_concurrent_operations == 0
            || values.iter().any(|value| *value > MAX_SAFE_JSON_INTEGER)
            || self
                .active_operations
                .checked_add(self.reserved_operations)
                .and_then(|used| used.checked_add(self.available_operation_slots))
                .is_none_or(|reported| reported > self.max_concurrent_operations)
        {
            return Err(WorkerContractError::Invalid("invalid worker capacity"));
        }
        Ok(())
    }
}

impl WorkerCapabilities {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        WorkerScope {
            services: self.services.clone(),
            max_concurrent_operations: self.capacity.max_concurrent_operations,
        }
        .validate()?;
        self.capacity.validate()
    }
}

impl WorkerRevocationLease {
    pub fn validate(&self) -> Result<(), WorkerContractError> {
        validate_type_version(&self.lease_type, "WorkerRevocationLease", &self.version)?;
        validate_did(&self.issuer, "invalid issuer")?;
        validate_did(&self.provider_id, "invalid providerId")?;
        validate_token(&self.worker_id, "invalid workerId")?;
        validate_token(&self.delegation_id, "invalid delegationId")?;
        validate_token(&self.revocation_id, "invalid revocationId")?;
        validate_token(&self.environment, "invalid environment")?;
        validate_window(
            &self.issued_at,
            &self.expires_at,
            DEFAULT_MAX_REVOCATION_STALENESS_SECONDS as i64,
            "revocation lease",
        )
    }

    pub fn permits_new_work_at(&self, now: OffsetDateTime) -> bool {
        if self.validate().is_err() || self.status != RevocationStatus::Active {
            return false;
        }
        match (
            parse_timestamp(&self.issued_at, "revocation lease"),
            parse_timestamp(&self.expires_at, "revocation lease"),
        ) {
            (Ok(issued_at), Ok(expires_at)) => now >= issued_at && now <= expires_at,
            _ => false,
        }
    }
}

fn validate_protocol_versions(versions: &[String]) -> Result<(), WorkerContractError> {
    if versions != ["1"] {
        return Err(WorkerContractError::Invalid("invalid protocol versions"));
    }
    Ok(())
}

fn validate_type_version(
    actual_type: &str,
    expected_type: &'static str,
    version: &str,
) -> Result<(), WorkerContractError> {
    if actual_type != expected_type || version != WORKER_CONTRACT_VERSION {
        return Err(WorkerContractError::Invalid("unsupported type or version"));
    }
    Ok(())
}

fn validate_worker_key(worker_did: &str, key_id: &str) -> Result<(), WorkerContractError> {
    validate_did(worker_did, "invalid workerDid")?;
    if !key_id
        .strip_prefix(worker_did)
        .is_some_and(|fragment| fragment.starts_with('#') && fragment.len() > 1)
    {
        return Err(WorkerContractError::Invalid("invalid keyId"));
    }
    Ok(())
}

fn validate_did(value: &str, error: &'static str) -> Result<(), WorkerContractError> {
    if !value.starts_with("did:web:")
        || value.len() <= "did:web:".len()
        || value.len() > 512
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(WorkerContractError::Invalid(error));
    }
    Ok(())
}

fn validate_token(value: &str, error: &'static str) -> Result<(), WorkerContractError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(WorkerContractError::Invalid(error));
    }
    Ok(())
}

fn validate_audience(value: &str) -> Result<(), WorkerContractError> {
    if !value.starts_with("https://")
        || value.len() <= "https://".len()
        || value.len() > 2_048
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(WorkerContractError::Invalid("invalid audience"));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), WorkerContractError> {
    let valid = value.len() <= 128
        && !value.contains('=')
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() >= 32);
    if !valid {
        return Err(WorkerContractError::Invalid("invalid nonce"));
    }
    Ok(())
}

fn validate_compact_jws(value: &str, error: &'static str) -> Result<(), WorkerContractError> {
    let mut segments = value.split('.');
    if !(segments.next().is_some_and(|segment| !segment.is_empty())
        && segments.next().is_some_and(|segment| !segment.is_empty())
        && segments.next().is_some_and(|segment| !segment.is_empty())
        && segments.next().is_none())
    {
        return Err(WorkerContractError::Invalid(error));
    }
    Ok(())
}

fn validate_digest(value: &str, error: &'static str) -> Result<(), WorkerContractError> {
    if value.len() != 43
        || value.contains('=')
        || !URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|digest| digest.len() == 32)
    {
        return Err(WorkerContractError::Invalid(error));
    }
    Ok(())
}

fn validate_hash(value: &str, error: &'static str) -> Result<(), WorkerContractError> {
    let Some(encoded) = value.strip_prefix("urn:sha256:") else {
        return Err(WorkerContractError::Invalid(error));
    };
    validate_digest(encoded, error)
}

fn validate_window(
    start: &str,
    end: &str,
    max_seconds: i64,
    name: &'static str,
) -> Result<(), WorkerContractError> {
    let start = parse_timestamp(start, name)?;
    let end = parse_timestamp(end, name)?;
    let duration = end - start;
    if !duration.is_positive() || duration.whole_seconds() > max_seconds {
        return Err(WorkerContractError::InvalidTimeWindow(name));
    }
    Ok(())
}

fn parse_timestamp(value: &str, name: &'static str) -> Result<OffsetDateTime, WorkerContractError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| WorkerContractError::InvalidTimestamp(name))
}
