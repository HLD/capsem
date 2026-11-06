use super::*;

#[test]
fn memory_injection_resolves_without_creating_disk_state_and_loses_on_restart() {
    let store = CredentialStore::default();
    let reference = store
        .inject(
            CredentialProvider::OpenAi,
            "injected-secret",
            CredentialPersistence::Memory,
        )
        .unwrap();
    assert_eq!(
        reference,
        capsem_proto::credential_reference::credential_reference("openai", "injected-secret")
    );
    assert_eq!(
        store
            .resolve(CredentialProvider::OpenAi, &reference)
            .unwrap()
            .as_deref(),
        Some("injected-secret")
    );
    assert_eq!(store.memory_credentials().unwrap().len(), 1);
    assert!(!format!("{:?}", store.memory_credentials().unwrap()).contains("injected-secret"));
    assert!(!CredentialStore::default().replay_available_in_memory(CredentialProvider::OpenAi, &reference));
}

#[test]
fn host_handoff_validates_entire_batch_before_mutating_memory() {
    let source = CredentialStore::default();
    let reference = source
        .inject(
            CredentialProvider::Github,
            "injected-secret",
            CredentialPersistence::Memory,
        )
        .unwrap();
    let target = CredentialStore::default();
    let mut entries = source.memory_credentials().unwrap();
    let mut invalid = entries[0].clone();
    invalid.provider = "openai".into();
    entries.push(invalid);
    assert!(target.import_memory_credentials(entries).is_err());
    assert_eq!(target.status().cached_count, 0);
    target
        .import_memory_credentials(source.memory_credentials().unwrap())
        .unwrap();
    assert_eq!(
        target
            .resolve(CredentialProvider::Github, &reference)
            .unwrap()
            .as_deref(),
        Some("injected-secret")
    );
    assert!(target.memory_credentials().unwrap().len() == 1);
}

#[test]
fn invalid_injection_is_redacted_and_does_not_enter_cache() {
    let store = CredentialStore::default();
    for secret in ["", "private\nsecret", "private\0secret"] {
        let error = store
            .inject(CredentialProvider::OpenAi, secret, CredentialPersistence::Memory)
            .unwrap_err();
        assert!(!error.contains("private"));
    }
    assert_eq!(store.status().cached_count, 0);
}

#[test]
fn capture_limit_refuses_new_secret_without_caching_it() {
    let store = CredentialStore::default();
    for index in 0..durable::MAX_CAPTURED_CREDENTIALS {
        store
            .cache_insert(&CredentialProvider::OpenAi.into(), &format!("ref-{index}"), "existing")
            .unwrap();
    }
    let error = store
        .capture(CredentialProvider::OpenAi, "new-ref", "new-secret")
        .unwrap_err();
    assert!(error.contains("full"));
    assert_eq!(store.status().cached_count, durable::MAX_CAPTURED_CREDENTIALS);
    assert_eq!(
        store.cache_get(&CredentialProvider::OpenAi.into(), "new-ref").unwrap(),
        None
    );
    assert!(!store.capture(CredentialProvider::OpenAi, "ref-0", "existing").unwrap());
}

#[test]
fn bound_injection_resolves_only_through_its_own_binding() {
    let store = CredentialStore::default();
    let reference = store
        .inject_bound("stripe", "bound-secret-value", CredentialPersistence::Memory)
        .unwrap();
    assert_eq!(
        reference,
        capsem_proto::credential_reference::credential_reference("http:stripe", "bound-secret-value")
    );
    assert_eq!(
        store.resolve_bound("stripe", &reference).unwrap().as_deref(),
        Some("bound-secret-value")
    );
    assert_eq!(
        store
            .cache_get(&CredentialNamespace::binding("linear").unwrap(), &reference)
            .unwrap(),
        None
    );
    for provider in CredentialProvider::all() {
        assert_eq!(
            store.cache_get(&(*provider).into(), &reference).unwrap(),
            None,
            "{provider:?}"
        );
    }

    let provider_reference = store
        .inject(
            CredentialProvider::OpenAi,
            "bound-secret-value",
            CredentialPersistence::Memory,
        )
        .unwrap();
    assert_ne!(provider_reference, reference, "the binding is the reference domain");
}

#[test]
fn bound_injection_refuses_invalid_binding_ids() {
    let store = CredentialStore::default();
    for id in ["", "Stripe", "a:b"] {
        assert!(store
            .inject_bound(id, "bound-secret-value", CredentialPersistence::Memory)
            .is_err());
        assert!(store.resolve_bound(id, "credential:blake3:00").is_err());
    }
    assert_eq!(store.status().cached_count, 0);
}

#[test]
fn host_handoff_carries_bound_and_provider_memory_credentials_together() {
    let source = CredentialStore::default();
    let bound = source
        .inject_bound("stripe", "bound-secret-value", CredentialPersistence::Memory)
        .unwrap();
    let provider = source
        .inject(
            CredentialProvider::Github,
            "github-secret-value",
            CredentialPersistence::Memory,
        )
        .unwrap();
    let entries = source.memory_credentials().unwrap();
    assert!(entries
        .iter()
        .any(|entry| entry.provider == "http:stripe" && entry.credential_ref == bound));

    let target = CredentialStore::default();
    target.import_memory_credentials(entries).unwrap();
    assert_eq!(
        target.resolve_bound("stripe", &bound).unwrap().as_deref(),
        Some("bound-secret-value")
    );
    assert_eq!(
        target
            .resolve(CredentialProvider::Github, &provider)
            .unwrap()
            .as_deref(),
        Some("github-secret-value")
    );

    let mut moved = source.memory_credentials().unwrap();
    for entry in &mut moved {
        if entry.provider == "http:stripe" {
            entry.provider = "http:linear".into();
        }
    }
    assert!(
        CredentialStore::default().import_memory_credentials(moved).is_err(),
        "a reference cannot be re-homed to another binding in transit"
    );
}
