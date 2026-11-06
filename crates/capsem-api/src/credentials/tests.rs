use super::*;

#[test]
fn injection_openapi_declares_write_only_material_and_reference_only_response() {
    let doc = serde_json::to_value(crate::openapi()).unwrap();
    assert_eq!(
        doc["paths"]["/credentials/inject"]["post"]["operationId"],
        "injectCredential"
    );
    assert_eq!(
        doc["components"]["schemas"]["CredentialInjectRequest"]["properties"]["value"]["writeOnly"],
        true
    );
    let response = &doc["components"]["schemas"]["CredentialInjectResponse"]["properties"];
    assert_eq!(response.as_object().unwrap().len(), 2);
    assert!(response["value"].is_null());
}

#[test]
fn injection_contract_defaults_to_file_and_never_debugs_material() {
    let request: CredentialInjectRequest =
        serde_json::from_str(r#"{"provider":"openai","value":"private-token"}"#).unwrap();
    assert_eq!(request.storage, CredentialStorage::File);
    assert!(!format!("{request:?}").contains("private-token"));
    assert!(
        serde_json::from_str::<CredentialInjectRequest>(r#"{"provider":"invalid","value":"private-token"}"#).is_err()
    );
    assert!(serde_json::from_str::<CredentialInjectRequest>(
        r#"{"provider":"openai","value":"private-token","unexpected":true}"#
    )
    .is_err());
    let response = CredentialInjectResponse {
        credential_ref: "credential:blake3:opaque".into(),
        storage: CredentialStorage::Memory,
    };
    let encoded = serde_json::to_value(response).unwrap();
    assert_eq!(encoded["storage"], "memory");
    assert_eq!(encoded.as_object().unwrap().len(), 2);
}

#[test]
fn http_injection_names_a_binding_and_keeps_material_out_of_debug() {
    let request: CredentialInjectRequest =
        serde_json::from_str(r#"{"provider":"http","binding":"stripe","value":"private-token"}"#).unwrap();
    assert_eq!(request.provider, CredentialInjectProvider::Http);
    assert_eq!(request.binding.as_deref(), Some("stripe"));
    let debug = format!("{request:?}");
    assert!(debug.contains("stripe") && !debug.contains("private-token"));
    let built_in: CredentialInjectRequest =
        serde_json::from_str(r#"{"provider":"openai","value":"private-token"}"#).unwrap();
    assert_eq!(built_in.binding, None);
    let doc = serde_json::to_value(crate::openapi()).unwrap();
    let schema = &doc["components"]["schemas"]["CredentialInjectRequest"];
    assert!(schema["properties"]["binding"].is_object());
    assert!(!schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .any(|field| field == "binding"));
}
