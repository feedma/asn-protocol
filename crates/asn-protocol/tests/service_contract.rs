use asn_protocol::service::{
    DataContract, OperationContract, SERVICE_CONTRACT_VERSION, ServiceContract,
    WorkerServiceSupport,
};
use serde_json::json;

fn contract() -> ServiceContract {
    ServiceContract {
        contract_version: SERVICE_CONTRACT_VERSION.into(),
        service_id: "geojson-rendering".into(),
        service_version: "1.0.0".into(),
        name: "GeoJSON rendering".into(),
        description: "Renders geographic data as an image".into(),
        operations: vec![OperationContract {
            id: "geography.render".into(),
            description: "Render one GeoJSON document".into(),
            execution_modes: vec!["async".into()],
            input: DataContract {
                schema: json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "required": ["geojson"]
                }),
                media_types: vec!["application/json".into()],
                max_bytes: Some(10_485_760),
            },
            output: DataContract {
                schema: json!({"type": "object", "required": ["image"]}),
                media_types: vec!["application/json".into()],
                max_bytes: Some(20_971_520),
            },
            authorization_protocols: vec!["ap2".into()],
            payment_protocols: vec!["x402".into()],
        }],
    }
}

#[test]
fn contract_hash_is_stable_across_json_property_order_and_whitespace() {
    let first = contract();
    let reordered = format!(
        r#"{{
          "operations": {},
          "description": "Renders geographic data as an image",
          "name": "GeoJSON rendering",
          "serviceVersion": "1.0.0",
          "serviceId": "geojson-rendering",
          "contractVersion": "1"
        }}"#,
        serde_json::to_string(&first.operations).unwrap()
    );
    let second = ServiceContract::from_slice(reordered.as_bytes()).unwrap();

    assert_eq!(
        first.contract_hash().unwrap(),
        second.contract_hash().unwrap()
    );
    assert_eq!(
        first.contract_hash().unwrap(),
        "urn:sha256:dAL7LqUGJyt53mKyPMXrf8OlooGKSdsPj2_sqodCUFs"
    );
}

#[test]
fn ambiguous_contract_json_is_rejected() {
    let input = br#"{
      "contractVersion":"1",
      "serviceId":"one",
      "serviceId":"two",
      "serviceVersion":"1.0.0",
      "name":"Duplicate",
      "description":"Duplicate identifier",
      "operations":[]
    }"#;

    assert!(ServiceContract::from_slice(input).is_err());
}

#[test]
fn worker_support_is_bound_to_the_exact_contract() {
    let contract = contract();
    WorkerServiceSupport {
        service_id: contract.service_id.clone(),
        service_version: contract.service_version.clone(),
        contract_hash: contract.contract_hash().unwrap(),
    }
    .validate()
    .unwrap();
}

#[test]
fn invalid_schema_shape_and_duplicate_operation_are_rejected() {
    let mut invalid_schema = contract();
    invalid_schema.operations[0].input.schema = json!("not-a-json-schema");
    assert!(invalid_schema.validate().is_err());

    let mut duplicate = contract();
    duplicate.operations.push(duplicate.operations[0].clone());
    assert!(duplicate.validate().is_err());
}
