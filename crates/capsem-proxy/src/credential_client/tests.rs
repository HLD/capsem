use std::os::unix::net::UnixStream;

use capsem_core::credential_broker::UpstreamTarget;
use capsem_core::net::proxy_engine::ProxyCredentials;
use capsem_foundation::ipc_channel;
use capsem_proto::proxy_credentials::{ProxyCredentialRequest, ProxyCredentialResponse};

fn target() -> UpstreamTarget<'static> {
    UpstreamTarget {
        domain: "example.com",
        ai_provider: None,
        method: "GET",
        path: "/v1/items",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_substitution_preserves_correlated_headers_and_reports_disconnect() {
    let (service, proxy) = UnixStream::pair().unwrap();
    let (client, mut closed) = super::CredentialClient::start(proxy).unwrap();
    let serving = tokio::spawn(async move {
        let (sender, receiver) =
            ipc_channel::channel_from_std::<ProxyCredentialResponse, ProxyCredentialRequest>(service).unwrap();
        let ProxyCredentialRequest::Substitute {
            request_id,
            method,
            path,
            headers,
            query,
            ..
        } = receiver.recv().await.unwrap()
        else {
            panic!("expected substitution request")
        };
        assert_eq!((method.as_str(), path.as_str()), ("GET", "/v1/items"));
        sender
            .send(ProxyCredentialResponse::Substituted {
                request_id,
                headers,
                query,
                credential_ref: Some("credential:blake3:test".to_string()),
                bound: vec![capsem_proto::proxy_credentials::ProxyBoundReference {
                    credential_ref: "credential:blake3:test".to_string(),
                    binding: "svc".to_string(),
                }],
            })
            .await
            .unwrap();
    });
    let mut headers = http::HeaderMap::new();
    headers.insert("x-test", http::HeaderValue::from_static("ordinary"));
    let result = client
        .substitute_upstream(target(), &mut headers, Some("page=1"))
        .unwrap();
    assert_eq!(headers["x-test"], "ordinary");
    assert_eq!(result.query.as_deref(), Some("page=1"));
    assert_eq!(result.credential_ref.as_deref(), Some("credential:blake3:test"));
    assert_eq!(
        result.bound,
        vec![capsem_core::credential_broker::BoundReference {
            credential_ref: "credential:blake3:test".to_string(),
            binding: "svc".to_string(),
        }],
        "the binding crosses the confined-proxy boundary"
    );
    serving.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), closed.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        *closed.borrow(),
        Some(capsem_proto::proxy_control::ProxyChannelCloseReason::Disconnected)
    );
}

#[test]
fn remote_substitution_does_not_panic_on_the_proxy_current_thread_runtime() {
    let (service, proxy) = UnixStream::pair().unwrap();
    let (client, _closed) = super::CredentialClient::start(proxy).unwrap();
    let serving = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (sender, receiver) =
                ipc_channel::channel_from_std::<ProxyCredentialResponse, ProxyCredentialRequest>(service).unwrap();
            let ProxyCredentialRequest::Substitute {
                request_id, headers, ..
            } = receiver.recv().await.unwrap()
            else {
                panic!("expected substitution request")
            };
            sender
                .send(ProxyCredentialResponse::Substituted {
                    request_id,
                    headers,
                    query: None,
                    credential_ref: None,
                    bound: Vec::new(),
                })
                .await
                .unwrap();
        });
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        client
            .substitute_upstream(target(), &mut http::HeaderMap::new(), None)
            .unwrap();
    });
    serving.join().unwrap();
}
