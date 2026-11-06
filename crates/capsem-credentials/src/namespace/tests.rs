use super::*;

const REF: &str = "credential:blake3:0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn binding_ids_use_the_config_identifier_shape() {
    for id in ["stripe", "linear-prod", "svc_2"] {
        assert!(CredentialNamespace::binding(id).is_ok(), "{id}");
    }
    for id in ["", "Stripe", "a:b", "a.b", "a b", &"x".repeat(65)] {
        assert!(CredentialNamespace::binding(id).is_err(), "{id:?}");
    }
}

#[test]
fn accounts_round_trip_for_providers_and_bindings() {
    for namespace in [
        CredentialNamespace::Provider(CredentialProvider::Anthropic),
        CredentialNamespace::Provider(CredentialProvider::Mcp),
        CredentialNamespace::binding("stripe").unwrap(),
    ] {
        let account = namespace.account(REF);
        assert_eq!(
            CredentialNamespace::parse_account(&account),
            Some((namespace.clone(), REF)),
            "{account}"
        );
    }
    assert_eq!(
        CredentialNamespace::binding("stripe").unwrap().account(REF),
        format!("http:stripe:{REF}")
    );
}

#[test]
fn provider_accounts_keep_their_existing_spelling() {
    assert_eq!(
        CredentialNamespace::from(CredentialProvider::Github).account(REF),
        crate::credential_store_account(CredentialProvider::Github, REF)
    );
}

#[test]
fn unknown_or_malformed_accounts_are_not_owned() {
    for account in [
        "",
        "nope:credential:blake3:00",
        "http:",
        "http:stripe",
        "http::credential:blake3:00",
        "http:Bad:credential:blake3:00",
        "anthropic",
    ] {
        assert_eq!(CredentialNamespace::parse_account(account), None, "{account:?}");
    }
}
