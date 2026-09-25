use asn_protocol::{
    identity::PublicJwk,
    service::WorkerServiceSupport,
    worker::{
        CreateWorkerEnrollmentChallenge, DurableCursors, RevocationStatus, SessionChallenge,
        SessionHello, WorkerCapacity, WorkerContractError, WorkerDelegation,
        WorkerEnrollmentChallenge, WorkerEnrollmentProof, WorkerRevocationLease, WorkerScope,
        WorkerSessionProof,
    },
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const CONTRACT_HASH: &str = "urn:sha256:dAL7LqUGJyt53mKyPMXrf8OlooGKSdsPj2_sqodCUFs";
const THUMBPRINT: &str = "gWjt7nmB1udyFpLYVp0SxJnI8lJEvl7q8AFYZRqnGV8";
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn at(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

fn service() -> WorkerServiceSupport {
    WorkerServiceSupport {
        service_id: "geojson-rendering".into(),
        service_version: "1.0.0".into(),
        contract_hash: CONTRACT_HASH.into(),
    }
}

fn scope(max_concurrent_operations: u64) -> WorkerScope {
    WorkerScope {
        services: vec![service()],
        max_concurrent_operations,
    }
}

fn request() -> CreateWorkerEnrollmentChallenge {
    CreateWorkerEnrollmentChallenge {
        provider_id: "did:web:provider.example".into(),
        worker_did: "did:web:worker.example".into(),
        public_key_jwk: PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "HhhTL9R1TALzBB2cdc6zO4P_2BrHzk_ogsyxyYvFiW4".into(),
            y: "pGwxHE4v9A3ZajZT5uRURdMt_khuztdcepDGoYiBwKM".into(),
        },
        key_id: "did:web:worker.example#key-2026-09".into(),
        requested_scope: scope(2),
        environment: "asn.example".into(),
    }
}

fn enrollment_challenge() -> WorkerEnrollmentChallenge {
    WorkerEnrollmentChallenge {
        challenge_id: "wch_01K".into(),
        nonce: NONCE.into(),
        audience: "https://asn.example/worker-enrollment".into(),
        expires_at: "2026-09-22T12:05:00Z".into(),
    }
}

fn enrollment_proof() -> WorkerEnrollmentProof {
    WorkerEnrollmentProof {
        proof_type: "WorkerEnrollmentProof".into(),
        version: "1".into(),
        challenge_id: "wch_01K".into(),
        nonce: NONCE.into(),
        provider_id: "did:web:provider.example".into(),
        worker_did: "did:web:worker.example".into(),
        key_id: "did:web:worker.example#key-2026-09".into(),
        public_key_thumbprint: THUMBPRINT.into(),
        requested_scope_hash: request().requested_scope.hash().unwrap(),
        environment: "asn.example".into(),
        audience: "https://asn.example/worker-enrollment".into(),
        issued_at: "2026-09-22T12:01:00Z".into(),
        expires_at: "2026-09-22T12:04:00Z".into(),
    }
}

fn delegation() -> WorkerDelegation {
    WorkerDelegation {
        delegation_type: "WorkerDelegation".into(),
        version: "1".into(),
        delegation_id: "wdl_01K".into(),
        provider_id: "did:web:provider.example".into(),
        worker_did: "did:web:worker.example".into(),
        key_id: "did:web:worker.example#key-2026-09".into(),
        public_key_thumbprint: THUMBPRINT.into(),
        scope: scope(4),
        environment: "asn.example".into(),
        protocol_version: "1".into(),
        not_before: "2026-09-22T00:00:00Z".into(),
        expires_at: "2026-10-22T00:00:00Z".into(),
        revocation_id: "rev_01K".into(),
        max_revocation_staleness_seconds: 300,
    }
}

#[test]
fn enrollment_proof_binds_challenge_key_scope_and_environment() {
    let request = request();
    enrollment_proof()
        .validate_for(
            &request,
            &enrollment_challenge(),
            at("2026-09-22T12:02:00Z"),
        )
        .unwrap();

    let mut cross_environment = request.clone();
    cross_environment.environment = "other.example".into();
    assert_eq!(
        enrollment_proof()
            .validate_for(
                &cross_environment,
                &enrollment_challenge(),
                at("2026-09-22T12:02:00Z")
            )
            .unwrap_err(),
        WorkerContractError::BindingMismatch("enrollment request")
    );

    assert_eq!(
        enrollment_proof()
            .validate_for(
                &request,
                &enrollment_challenge(),
                at("2026-09-22T12:06:00Z")
            )
            .unwrap_err(),
        WorkerContractError::InvalidTimeWindow("expired enrollment challenge")
    );
}

#[test]
fn provider_delegation_can_narrow_but_not_expand_exact_service_scope() {
    delegation()
        .authorize(&request(), at("2026-09-22T12:02:00Z"))
        .unwrap();

    let mut too_narrow = delegation();
    too_narrow.scope.max_concurrent_operations = 1;
    assert_eq!(
        too_narrow
            .authorize(&request(), at("2026-09-22T12:02:00Z"))
            .unwrap_err(),
        WorkerContractError::BindingMismatch("delegated scope")
    );

    let mut wrong_contract = delegation();
    wrong_contract.scope.services[0].contract_hash =
        "urn:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    assert_eq!(
        wrong_contract
            .authorize(&request(), at("2026-09-22T12:02:00Z"))
            .unwrap_err(),
        WorkerContractError::BindingMismatch("delegated scope")
    );
}

#[test]
fn session_proof_binds_identity_environment_and_durable_cursors() {
    let hello = SessionHello {
        worker_id: "wrk_01K".into(),
        credential: "opaque-credential".into(),
        supported_protocol_versions: vec!["1".into()],
        cursors: DurableCursors {
            worker_to_gateway: 41,
            gateway_to_worker: 17,
        },
    };
    let challenge = SessionChallenge {
        session_id: "wss_01K".into(),
        nonce: NONCE.into(),
        audience: "https://asn.example/worker-gateway".into(),
        expires_at: "2026-09-22T12:03:00Z".into(),
    };
    let mut proof = WorkerSessionProof {
        proof_type: "WorkerSessionProof".into(),
        version: "1".into(),
        session_id: challenge.session_id.clone(),
        nonce: challenge.nonce.clone(),
        worker_id: hello.worker_id.clone(),
        environment: "asn.example".into(),
        audience: challenge.audience.clone(),
        cursors: hello.cursors.clone(),
        issued_at: "2026-09-22T12:02:10Z".into(),
        expires_at: "2026-09-22T12:02:50Z".into(),
    };

    proof
        .validate_for(
            &hello,
            &challenge,
            "asn.example",
            at("2026-09-22T12:02:20Z"),
        )
        .unwrap();
    proof.cursors.worker_to_gateway = 40;
    assert_eq!(
        proof
            .validate_for(
                &hello,
                &challenge,
                "asn.example",
                at("2026-09-22T12:02:20Z")
            )
            .unwrap_err(),
        WorkerContractError::BindingMismatch("worker session")
    );
}

#[test]
fn capacity_reports_only_consistent_concurrent_operation_slots() {
    WorkerCapacity {
        max_concurrent_operations: 4,
        active_operations: 1,
        reserved_operations: 1,
        available_operation_slots: 2,
    }
    .validate()
    .unwrap();

    WorkerCapacity {
        max_concurrent_operations: 4,
        active_operations: 1,
        reserved_operations: 1,
        available_operation_slots: 0,
    }
    .validate()
    .unwrap();

    assert!(
        WorkerCapacity {
            max_concurrent_operations: 4,
            active_operations: 1,
            reserved_operations: 1,
            available_operation_slots: 3,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn revocation_lease_stops_new_work_when_revoked_or_stale() {
    let mut lease = WorkerRevocationLease {
        lease_type: "WorkerRevocationLease".into(),
        version: "1".into(),
        issuer: "did:web:asn.example:revocation".into(),
        provider_id: "did:web:provider.example".into(),
        worker_id: "wrk_01K".into(),
        delegation_id: "wdl_01K".into(),
        revocation_id: "rev_01K".into(),
        environment: "asn.example".into(),
        status: RevocationStatus::Active,
        issued_at: "2026-09-22T12:00:00Z".into(),
        expires_at: "2026-09-22T12:05:00Z".into(),
    };
    assert!(lease.permits_new_work_at(at("2026-09-22T12:04:59Z")));
    assert!(!lease.permits_new_work_at(at("2026-09-22T12:05:01Z")));
    lease.status = RevocationStatus::Revoked;
    assert!(!lease.permits_new_work_at(at("2026-09-22T12:04:00Z")));
}
