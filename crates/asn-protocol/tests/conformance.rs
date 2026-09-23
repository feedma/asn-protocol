use asn_protocol::canonical::canonicalize;
use asn_protocol::identity::{
    PublicJwk, SignerError, VerificationKey, build_compact_jws, verify_compact_jws,
};
use asn_protocol::signers::JwsSigner;
use asn_protocol::wire::{Envelope, EnvelopeError};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde_json::json;

#[test]
fn ambiguous_or_non_json_inputs_are_rejected() {
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"nested":{"a":1,"\u0061":2}}"#,
        r#"{"loneSurrogate":"\ud800"}"#,
        "1e9999",
        "{} {}",
    ] {
        assert!(canonicalize(input.as_bytes()).is_err(), "{input}");
    }
}

#[test]
fn rfc8785_numbers_and_utf16_property_order() {
    // RFC 8785 sections 3.2.2.3 and 3.2.3. UTF-8 ordering would put U+FB33 first.
    let input = r#"{ "דּ": 4.50, "😀": 1e30, "a": [2e-3, 1e-27, -0.0] }"#;
    assert_eq!(
        String::from_utf8(canonicalize(input.as_bytes()).unwrap()).unwrap(),
        r#"{"a":[0.002,1e-27,0],"😀":1e+30,"דּ":4.5}"#
    );
}

#[test]
fn version_one_envelope_round_trips_with_extensions() {
    let input = br#"{"version":"1","type":"worker.heartbeat","messageId":"msg_01","sequence":42,"sentAt":"2026-09-22T12:02:00Z","correlationId":null,"body":{"activeAttempts":0},"proof":null,"futureField":{"keep":true}}"#;
    let envelope = Envelope::from_slice(input).unwrap();

    assert_eq!(envelope.message_type, "worker.heartbeat");
    assert_eq!(envelope.body, json!({"activeAttempts": 0}));
    assert_eq!(envelope.extensions["futureField"], json!({"keep": true}));
    assert_eq!(
        envelope.to_canonical_vec().unwrap(),
        canonicalize(input).unwrap()
    );
}

#[test]
fn unsupported_or_malformed_envelope_versions_are_explicit() {
    for (version, expected) in [
        ("2", EnvelopeError::UnsupportedMajor(2)),
        ("1.1", EnvelopeError::MalformedVersion),
        ("01", EnvelopeError::MalformedVersion),
    ] {
        let input = format!(
            r#"{{"version":"{version}","type":"ack","messageId":"msg_01","sequence":1,"sentAt":"2026-09-22T12:02:00Z","correlationId":null,"body":{{}},"proof":null}}"#
        );
        assert_eq!(
            Envelope::from_slice(input.as_bytes()).unwrap_err(),
            expected
        );
    }
}

#[test]
fn envelope_sequence_must_be_an_interoperable_json_integer() {
    let input = br#"{"version":"1","type":"ack","messageId":"msg_01","sequence":9007199254740992,"sentAt":"2026-09-22T12:02:00Z","correlationId":null,"body":{},"proof":null}"#;
    assert_eq!(
        Envelope::from_slice(input).unwrap_err(),
        EnvelopeError::InvalidSequence
    );
}

#[test]
fn unsupported_envelope_cannot_be_serialized_for_transport() {
    let input = br#"{"version":"1","type":"ack","messageId":"msg_01","sequence":1,"sentAt":"2026-09-22T12:02:00Z","correlationId":null,"body":{},"proof":null}"#;
    let mut envelope = Envelope::from_slice(input).unwrap();
    envelope.version = "2".into();
    assert_eq!(
        envelope.to_canonical_vec().unwrap_err(),
        EnvelopeError::UnsupportedMajor(2)
    );
}

struct TestSigner {
    key: SigningKey,
    key_id: String,
}

impl JwsSigner for TestSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_jwk(&self) -> PublicJwk {
        verification_key(self).jwk
    }

    fn sign_es256(&self, signing_input: &[u8]) -> Result<[u8; 64], SignerError> {
        let signature: Signature = self.key.sign(signing_input);
        Ok(signature.to_bytes().into())
    }
}

fn test_signer() -> TestSigner {
    TestSigner {
        key: SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap(),
        key_id: "did:web:worker.example#key-1".into(),
    }
}

fn verification_key(signer: &TestSigner) -> VerificationKey {
    let point = signer.key.verifying_key().to_encoded_point(false);
    VerificationKey {
        key_id: signer.key_id.clone(),
        jwk: PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        },
        active: true,
    }
}

#[test]
fn inactive_key_is_rejected_before_signature_acceptance() {
    let signer = test_signer();
    let compact = build_compact_jws(&json!({"version": "1"}), &signer).unwrap();
    let mut key = verification_key(&signer);
    key.active = false;
    assert!(verify_compact_jws(&compact, &key).is_err());
}

#[test]
fn es256_jws_preserves_and_verifies_exact_canonical_payload() {
    let signer = test_signer();
    let payload = json!({
        "type": "WorkerSessionProof",
        "version": "1",
        "workerId": "worker_01",
        "nonce": "abc"
    });
    let compact = build_compact_jws(&payload, &signer).unwrap();
    let verified = verify_compact_jws(&compact, &verification_key(&signer)).unwrap();

    assert_eq!(verified.payload, payload);
    assert_eq!(verified.compact, compact);
    assert_eq!(verified.key_id, signer.key_id);
}

#[test]
fn es256_jws_rejects_noncanonical_payload_and_header_substitution() {
    let signer = test_signer();
    let compact = build_compact_jws(&json!({"a": 1, "b": 2}), &signer).unwrap();
    let parts: Vec<_> = compact.split('.').collect();

    let noncanonical = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(br#"{ "b": 2, "a": 1 }"#),
        parts[2]
    );
    assert!(verify_compact_jws(&noncanonical, &verification_key(&signer)).is_err());

    let invalid_header = URL_SAFE_NO_PAD
        .encode(br#"{"alg":"none","kid":"did:web:worker.example#key-1","typ":"asn-worker+jws"}"#);
    let substituted = format!("{invalid_header}.{}.{}", parts[1], parts[2]);
    assert!(verify_compact_jws(&substituted, &verification_key(&signer)).is_err());
}
