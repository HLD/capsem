use super::*;
use crate::test_gateway::Server;
use crate::Hypervisor;

#[tokio::test]
async fn injection_preserves_auth_material_storage_and_no_replay_on_refusal() {
    let reference = format!("credential:blake3:{}", "a".repeat(64));
    let body = serde_json::json!({"credential_ref": reference, "storage":"memory"}).to_string();
    let mut server = Server::reply(200, body.as_bytes(), None).await;
    let hv = Hypervisor::new(&server.url, "private-token").unwrap();
    let response = hv
        .credentials()
        .inject(
            models::CredentialInjectProvider::Openai,
            "private-injected-key",
            models::CredentialStorage::Memory,
        )
        .await
        .unwrap();
    assert_eq!(response.credential_ref, reference);
    let (parts, bytes) = server.received.recv().await.unwrap();
    assert_eq!(parts.method, "POST");
    assert_eq!(parts.uri, "/credentials/inject");
    assert_eq!(parts.headers["authorization"], "Bearer private-token");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({"provider":"openai","value":"private-injected-key","storage":"memory"})
    );
    assert!(server.received.try_recv().is_err());
    let mut refused = Server::reply(503, b"handoff unavailable", None).await;
    let hv = Hypervisor::new(&refused.url, "private-token").unwrap();
    assert!(matches!(
        hv.credentials()
            .inject(
                models::CredentialInjectProvider::Google,
                "private-injected-key",
                models::CredentialStorage::Memory
            )
            .await,
        Err(Error::Http { status: 503, .. })
    ));
    refused.received.recv().await.unwrap();
    assert!(refused.received.try_recv().is_err());
}

#[tokio::test]
async fn bound_injection_names_its_binding_and_plain_injection_refuses_http() {
    let reference = format!("credential:blake3:{}", "b".repeat(64));
    let body = serde_json::json!({"credential_ref": reference, "storage":"file"}).to_string();
    let mut server = Server::reply(200, body.as_bytes(), None).await;
    let hv = Hypervisor::new(&server.url, "private-token").unwrap();
    let response = hv
        .credentials()
        .inject_bound("stripe", "private-bound-key", models::CredentialStorage::File)
        .await
        .unwrap();
    assert_eq!(response.credential_ref, reference);
    let (_, bytes) = server.received.recv().await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({"provider":"http","binding":"stripe","value":"private-bound-key","storage":"file"})
    );
    assert!(matches!(
        hv.credentials()
            .inject(
                models::CredentialInjectProvider::Http,
                "private-bound-key",
                models::CredentialStorage::File
            )
            .await,
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        hv.credentials()
            .inject_bound("", "private-bound-key", models::CredentialStorage::File)
            .await,
        Err(Error::InvalidInput(_))
    ));
    assert!(
        server.received.try_recv().is_err(),
        "refused inputs never reach the gateway"
    );
}
