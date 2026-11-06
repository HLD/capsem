use std::collections::HashMap;

use super::*;

const STRIPE_SECRET: &str = "rk_test_bound_secret_stripe_0001";
const LINEAR_SECRET: &str = "lin_api_bound_secret_linear_0002";
const MAPS_SECRET: &str = "maps key/with+reserved=chars&0003";

fn reference(binding: &str, raw: &str) -> String {
    capsem_logger::credential_reference(&format!("http:{binding}"), raw)
}

fn bindings() -> CredentialBindings {
    #[derive(serde::Deserialize)]
    struct Doc {
        credential_bindings: CredentialBindings,
    }
    toml::from_str::<Doc>(
        r#"
[credential_bindings.stripe]
hosts = ["api.stripe.com"]
placement = { header = "authorization", scheme = "Bearer" }
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]

[credential_bindings.linear]
hosts = ["api.linear.app"]
placement = { header = "x-api-key" }

[credential_bindings.linear-shadow]
hosts = ["api.linear.app"]
placement = { header = "authorization", scheme = "Bearer" }

[credential_bindings.maps]
hosts = ["*.maps.example.com"]
placement = { query = "key" }
"#,
    )
    .unwrap()
    .credential_bindings
}

struct Store(HashMap<(String, String), String>);

impl Store {
    fn new(entries: &[(&str, &str)]) -> Self {
        Self(
            entries
                .iter()
                .map(|(binding, raw)| ((binding.to_string(), reference(binding, raw)), raw.to_string()))
                .collect(),
        )
    }

    fn substitute(
        &self,
        target: UpstreamTarget<'_>,
        headers: &mut http::HeaderMap,
        query: Option<&str>,
    ) -> Result<Option<BrokeredUpstreamCredentials>, String> {
        let resolve = |binding: &str, credential_ref: &str| {
            self.0.get(&(binding.to_string(), credential_ref.to_string())).cloned()
        };
        substitute_bound(target, &bindings(), &resolve, headers, query)
    }
}

fn all() -> Store {
    Store::new(&[
        ("stripe", STRIPE_SECRET),
        ("linear", LINEAR_SECRET),
        ("linear-shadow", LINEAR_SECRET),
        ("maps", MAPS_SECRET),
    ])
}

fn target<'a>(domain: &'a str, method: &'a str, path: &'a str) -> UpstreamTarget<'a> {
    UpstreamTarget {
        domain,
        ai_provider: None,
        method,
        path,
    }
}

fn header(name: &'static str, value: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(name, http::HeaderValue::from_str(value).unwrap());
    headers.insert("x-trace", http::HeaderValue::from_static("ordinary"));
    headers
}

fn assert_refused(result: Result<Option<BrokeredUpstreamCredentials>, String>, headers: &http::HeaderMap) {
    assert_eq!(result.unwrap_err(), REFUSED);
    for value in headers.values() {
        let value = value.to_str().unwrap();
        for secret in [STRIPE_SECRET, LINEAR_SECRET, MAPS_SECRET] {
            assert!(!value.contains(secret), "secret leaked into {value:?}");
        }
    }
}

#[test]
fn bound_bearer_header_is_substituted_on_its_host() {
    let stripe = reference("stripe", STRIPE_SECRET);
    let mut headers = header("authorization", &format!("Bearer {stripe}"));
    let result = all()
        .substitute(target("api.stripe.com", "POST", "/v1/charges"), &mut headers, None)
        .unwrap()
        .expect("binding names the host");
    assert_eq!(headers["authorization"], format!("Bearer {STRIPE_SECRET}"));
    assert_eq!(headers["x-trace"], "ordinary");
    assert_eq!(result.credential_ref.as_deref(), Some(stripe.as_str()));
    assert_eq!(result.query, None);
}

#[test]
fn sent_scheme_spelling_is_preserved() {
    let stripe = reference("stripe", STRIPE_SECRET);
    let mut headers = header("authorization", &format!("bearer {stripe}"));
    all()
        .substitute(target("API.STRIPE.COM.", "GET", "/v1/x"), &mut headers, None)
        .unwrap()
        .unwrap();
    assert_eq!(headers["authorization"], format!("bearer {STRIPE_SECRET}"));
}

#[test]
fn bare_header_placement_is_substituted() {
    let linear = reference("linear", LINEAR_SECRET);
    let mut headers = header("x-api-key", &linear);
    all()
        .substitute(target("api.linear.app", "DELETE", "/anything"), &mut headers, None)
        .unwrap()
        .unwrap();
    assert_eq!(headers["x-api-key"], LINEAR_SECRET);
}

#[test]
fn percent_encoded_query_reference_is_substituted_and_reencoded() {
    let maps = reference("maps", MAPS_SECRET);
    let query = format!("q=coffee&key={}", maps.replace(':', "%3A"));
    let result = all()
        .substitute(
            target("tiles.maps.example.com", "GET", "/v1/tile"),
            &mut http::HeaderMap::new(),
            Some(&query),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        result.query.as_deref(),
        Some("q=coffee&key=maps%20key%2Fwith%2Breserved%3Dchars%260003")
    );
    assert_eq!(result.credential_ref.as_deref(), Some(maps.as_str()));
}

#[test]
fn hosts_without_bindings_are_left_to_the_caller() {
    let stripe = reference("stripe", STRIPE_SECRET);
    for host in [
        "evil.test",
        "evil-api.stripe.com",
        "api.stripe.com.evil.test",
        "maps.example.com",
    ] {
        let mut headers = header("authorization", &format!("Bearer {stripe}"));
        let result = all()
            .substitute(target(host, "GET", "/v1/x"), &mut headers, None)
            .unwrap();
        assert_eq!(result, None, "{host}");
        assert_eq!(headers["authorization"], format!("Bearer {stripe}"), "{host}");
    }
}

#[test]
fn reference_in_another_header_is_refused() {
    let stripe = reference("stripe", STRIPE_SECRET);
    let mut headers = header("x-forwarded-authorization", &format!("Bearer {stripe}"));
    let result = all().substitute(target("api.stripe.com", "GET", "/v1/x"), &mut headers, None);
    assert_refused(result, &headers);
}

#[test]
fn scheme_must_match_the_binding() {
    let stripe = reference("stripe", STRIPE_SECRET);
    for value in [stripe.clone(), format!("Token {stripe}"), format!("Basic {stripe}")] {
        let mut headers = header("authorization", &value);
        let result = all().substitute(target("api.stripe.com", "GET", "/v1/x"), &mut headers, None);
        assert_refused(result, &headers);
    }
    let linear = reference("linear", LINEAR_SECRET);
    let mut headers = header("x-api-key", &format!("Bearer {linear}"));
    let result = all().substitute(target("api.linear.app", "GET", "/"), &mut headers, None);
    assert_refused(result, &headers);
}

#[test]
fn reference_in_query_for_a_header_binding_is_refused() {
    let stripe = reference("stripe", STRIPE_SECRET);
    let mut headers = http::HeaderMap::new();
    let query = format!("key={stripe}");
    let result = all().substitute(target("api.stripe.com", "GET", "/v1/x"), &mut headers, Some(&query));
    assert_eq!(result.unwrap_err(), REFUSED);
}

#[test]
fn query_reference_under_another_key_is_refused() {
    let maps = reference("maps", MAPS_SECRET);
    for query in [
        format!("api_key={maps}"),
        format!("KEY={maps}"),
        format!("k%65y={maps}"),
    ] {
        let result = all().substitute(
            target("a.maps.example.com", "GET", "/"),
            &mut http::HeaderMap::new(),
            Some(&query),
        );
        assert_eq!(result.unwrap_err(), REFUSED, "{query}");
    }
}

#[test]
fn method_and_path_limits_are_enforced() {
    let stripe = reference("stripe", STRIPE_SECRET);
    for (method, path) in [
        ("DELETE", "/v1/charges"),
        ("GET", "/v2/charges"),
        ("GET", "/v1/../admin"),
        ("GET", "/v1/%2e%2e/admin"),
        ("", "/v1/charges"),
        ("GET", ""),
    ] {
        let mut headers = header("authorization", &format!("Bearer {stripe}"));
        let result = all().substitute(target("api.stripe.com", method, path), &mut headers, None);
        assert_refused(result, &headers);
    }
}

#[test]
fn reference_from_another_binding_is_refused_on_this_host() {
    let linear = reference("linear", LINEAR_SECRET);
    let mut headers = header("authorization", &format!("Bearer {linear}"));
    let result = all().substitute(target("api.stripe.com", "GET", "/v1/x"), &mut headers, None);
    assert_refused(result, &headers);
}

#[test]
fn built_in_provider_style_reference_is_refused_on_a_bound_host() {
    let openai = capsem_logger::credential_reference("openai", "sk-openai-not-for-stripe-0004");
    let mut headers = header("authorization", &format!("Bearer {openai}"));
    let result = all().substitute(target("api.stripe.com", "GET", "/v1/x"), &mut headers, None);
    assert_refused(result, &headers);
}

#[test]
fn several_bindings_on_one_host_each_resolve_their_own_placement() {
    let shadow = reference("linear-shadow", LINEAR_SECRET);
    let mut headers = header("authorization", &format!("Bearer {shadow}"));
    all()
        .substitute(target("api.linear.app", "GET", "/graphql"), &mut headers, None)
        .unwrap()
        .unwrap();
    assert_eq!(headers["authorization"], format!("Bearer {LINEAR_SECRET}"));
}

#[test]
fn revoked_material_is_refused() {
    let stripe = reference("stripe", STRIPE_SECRET);
    let mut headers = header("authorization", &format!("Bearer {stripe}"));
    let result = Store::new(&[]).substitute(target("api.stripe.com", "GET", "/v1/x"), &mut headers, None);
    assert_refused(result, &headers);
}

#[test]
fn requests_without_references_pass_through_on_bound_hosts() {
    let mut headers = header("authorization", "Bearer not-a-reference");
    let result = all()
        .substitute(
            target("api.stripe.com", "PUT", "/elsewhere"),
            &mut headers,
            Some("page=2"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(headers["authorization"], "Bearer not-a-reference");
    assert_eq!(
        result,
        BrokeredUpstreamCredentials {
            credential_ref: None,
            query: Some("page=2".to_string())
        }
    );
}

#[test]
fn built_in_provider_hosts_never_take_the_binding_path() {
    #[derive(serde::Deserialize)]
    struct Doc {
        credential_bindings: CredentialBindings,
    }
    let shadowing = toml::from_str::<Doc>(
        r#"
[credential_bindings.shadow]
hosts = ["api.openai.com"]
placement = { header = "authorization", scheme = "Bearer" }
"#,
    )
    .unwrap()
    .credential_bindings;
    let bound = reference("shadow", "sk-shadowed-binding-secret-0005");
    let mut headers = header("authorization", &format!("Bearer {bound}"));
    let result = super::super::substitute_brokered_upstream_credentials(
        target("api.openai.com", "POST", "/v1/responses"),
        &shadowing,
        &mut headers,
        None,
    );
    assert!(result.is_err(), "the built-in provider path owns this host");
    assert_eq!(headers["authorization"], format!("Bearer {bound}"));
}
