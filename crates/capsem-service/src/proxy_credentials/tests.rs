use std::os::unix::net::UnixStream;
use std::sync::Arc;

use capsem_core::net::policy_config::{ActivePolicyFile, SettingsFile};
use capsem_credentials::{CredentialPersistence, CredentialStore};
use capsem_foundation::ipc_channel;
use capsem_proto::proxy_credentials::{
    ProxyBoundReference, ProxyCredentialRequest, ProxyCredentialResponse, ProxyHeader, ProxyModelProvider,
};

use crate::upstream_broker::{policy_watch, BrokerPolicy};

const BINDINGS: &str = r#"
[credential_bindings.svc-proxy-test]
hosts = ["api.bound-service.test"]
placement = { header = "authorization", scheme = "Bearer" }
methods = ["GET"]
path_prefixes = ["/v1/"]
"#;

fn policy(settings: &str) -> Arc<BrokerPolicy> {
    let settings: SettingsFile = toml::from_str(settings).unwrap();
    let active = ActivePolicyFile::from_settings_and_corp(&settings, &SettingsFile::default()).unwrap();
    BrokerPolicy::new(
        format!("blake3:{}", "a".repeat(64)),
        Arc::new(active.compile_runtime().unwrap()),
    )
}

fn substitute(request_id: u64, domain: &str, path: &str, authorization: &str) -> ProxyCredentialRequest {
    ProxyCredentialRequest::Substitute {
        request_id,
        domain: domain.to_string(),
        ai_provider: None,
        method: "GET".to_string(),
        path: path.to_string(),
        headers: vec![ProxyHeader::new("authorization", authorization.as_bytes().to_vec())],
        query: None,
    }
}

#[tokio::test]
async fn substitution_round_trip_preserves_unbrokered_headers_and_query() {
    let (service, client) = UnixStream::pair().unwrap();
    let (watch, _publisher) = policy_watch(policy(""));
    let serving = tokio::spawn(super::serve(service, watch));
    let (sender, receiver) =
        ipc_channel::channel_from_std::<ProxyCredentialRequest, ProxyCredentialResponse>(client).unwrap();
    sender
        .send(ProxyCredentialRequest::Substitute {
            request_id: 7,
            domain: "example.com".to_string(),
            ai_provider: Some(ProxyModelProvider::Unknown),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![ProxyHeader::new("x-test", b"ordinary".to_vec())],
            query: Some("page=1".to_string()),
        })
        .await
        .unwrap();
    assert_eq!(
        receiver.recv().await.unwrap(),
        ProxyCredentialResponse::Substituted {
            request_id: 7,
            headers: vec![ProxyHeader::new("x-test", b"ordinary".to_vec())],
            query: Some("page=1".to_string()),
            credential_ref: None,
            bound: Vec::new(),
        }
    );
    drop(sender);
    drop(receiver);
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn bound_credential_follows_the_session_policy_and_its_updates() {
    let raw = "svc-proxy-test-bound-secret-0001";
    let reference = CredentialStore::global()
        .inject_bound("svc-proxy-test", raw, CredentialPersistence::Memory)
        .unwrap();
    let bearer = format!("Bearer {reference}");
    let (service, client) = UnixStream::pair().unwrap();
    let (watch, publisher) = policy_watch(policy(BINDINGS));
    let serving = tokio::spawn(super::serve(service, watch));
    let (sender, receiver) =
        ipc_channel::channel_from_std::<ProxyCredentialRequest, ProxyCredentialResponse>(client).unwrap();

    sender
        .send(substitute(1, "api.bound-service.test", "/v1/items", &bearer))
        .await
        .unwrap();
    assert_eq!(
        receiver.recv().await.unwrap(),
        ProxyCredentialResponse::Substituted {
            request_id: 1,
            headers: vec![ProxyHeader::new("authorization", format!("Bearer {raw}").into_bytes())],
            query: None,
            credential_ref: Some(reference.clone()),
            bound: vec![ProxyBoundReference {
                credential_ref: reference.clone(),
                binding: "svc-proxy-test".to_string(),
            }],
        }
    );

    for (request_id, domain, path) in [(2, "evil.test", "/v1/items"), (3, "api.bound-service.test", "/admin")] {
        sender
            .send(substitute(request_id, domain, path, &bearer))
            .await
            .unwrap();
        let ProxyCredentialResponse::Rejected { error, .. } = receiver.recv().await.unwrap() else {
            panic!("{domain}{path} must be refused");
        };
        assert!(!error.contains(raw));
    }

    publisher.publish(policy("")).await.unwrap();
    sender
        .send(substitute(4, "api.bound-service.test", "/v1/items", &bearer))
        .await
        .unwrap();
    assert!(
        matches!(
            receiver.recv().await.unwrap(),
            ProxyCredentialResponse::Rejected { request_id: 4, .. }
        ),
        "removing the binding from the session policy revokes its use"
    );

    drop(sender);
    drop(receiver);
    serving.await.unwrap().unwrap();
}
