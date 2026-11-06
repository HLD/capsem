use super::*;

#[derive(Debug, Deserialize)]
struct Doc {
    credential_bindings: CredentialBindings,
}

fn parse(toml_text: &str) -> Result<CredentialBindings, String> {
    toml::from_str::<Doc>(toml_text)
        .map(|doc| doc.credential_bindings)
        .map_err(|error| error.to_string())
}

fn one(body: &str) -> Result<CredentialBinding, String> {
    parse(&format!("[credential_bindings.svc]\n{body}"))
        .map(|bindings| bindings.get("svc").expect("binding present").clone())
}

fn bearer(hosts: &str) -> CredentialBinding {
    one(&format!(
        "hosts = {hosts}\nplacement = {{ header = \"Authorization\", scheme = \"Bearer\" }}"
    ))
    .expect("valid binding")
}

#[test]
fn parses_header_and_query_placements() {
    let bindings = parse(
        r#"
[credential_bindings.stripe]
hosts = ["api.stripe.com"]
placement = { header = "Authorization", scheme = "Bearer" }
methods = ["get", "POST", "GET"]
path_prefixes = ["/v1/"]

[credential_bindings.maps]
hosts = ["*.maps.example.com"]
placement = { query = "api_key" }
"#,
    )
    .expect("valid bindings");

    let stripe = bindings.get("stripe").unwrap();
    assert_eq!(
        stripe.placement(),
        &CredentialPlacement::Header {
            name: "authorization".into(),
            scheme: Some("Bearer".into())
        }
    );
    assert_eq!(
        stripe.methods,
        vec!["GET", "POST"],
        "methods are uppercased and deduplicated"
    );
    assert_eq!(
        bindings.get("maps").unwrap().placement(),
        &CredentialPlacement::Query { key: "api_key".into() }
    );
}

#[test]
fn round_trips_through_config_form() {
    let binding = one(
        "hosts = [\"API.Example.com.\", \"*.example.org\"]\nplacement = { header = \"x-api-key\" }\npath_prefixes = [\"/v2/\"]",
    )
    .unwrap();
    let text = toml::to_string(&binding).unwrap();
    let reparsed: CredentialBinding = toml::from_str(&text).unwrap();
    assert_eq!(reparsed, binding);
    assert!(
        text.contains("\"api.example.com\""),
        "hosts are stored normalized: {text}"
    );
    assert!(text.contains("\"*.example.org\""), "{text}");
}

#[test]
fn rejects_invalid_binding_ids() {
    for id in ["Stripe", "has space", "dot.ted", ""] {
        let text =
            format!("[credential_bindings.\"{id}\"]\nhosts = [\"a.example.com\"]\nplacement = {{ query = \"k\" }}");
        assert!(parse(&text).is_err(), "id {id:?} must be rejected");
    }
}

#[test]
fn rejects_unusable_hosts() {
    for hosts in [
        "[]",
        "[\"\"]",
        "[\"127.0.0.1\"]",
        "[\"::1\"]",
        "[\"[::1]\"]",
        "[\"example.123\"]",
        "[\"api.example.com:443\"]",
        "[\"api.example.com/v1\"]",
        "[\"user@api.example.com\"]",
        "[\"*\"]",
        "[\"*.com\"]",
        "[\"a.*.example.com\"]",
        "[\"**.example.com\"]",
        "[\"-bad.example.com\"]",
        "[\"bad..example.com\"]",
        "[\"under_score.example.com\"]",
    ] {
        let result = one(&format!("hosts = {hosts}\nplacement = {{ query = \"k\" }}"));
        assert!(result.is_err(), "hosts {hosts} must be rejected");
    }
}

#[test]
fn rejects_ambiguous_or_dangerous_placement() {
    for placement in [
        "{}",
        "{ header = \"authorization\", query = \"k\" }",
        "{ query = \"k\", scheme = \"Bearer\" }",
        "{ header = \"Host\" }",
        "{ header = \"content-length\" }",
        "{ header = \"Transfer-Encoding\" }",
        "{ header = \"proxy-authorization\" }",
        "{ header = \"bad header\" }",
        "{ header = \"\" }",
        "{ header = \"authorization\", scheme = \"Bear er\" }",
        "{ query = \"\" }",
        "{ query = \"a&b\" }",
        "{ query = \"a=b\" }",
        "{ header = \"x\", unknown = \"y\" }",
    ] {
        let result = one(&format!("hosts = [\"a.example.com\"]\nplacement = {placement}"));
        assert!(result.is_err(), "placement {placement} must be rejected");
    }
}

#[test]
fn rejects_unknown_methods_and_loose_prefixes() {
    let base = "hosts = [\"a.example.com\"]\nplacement = { query = \"k\" }\n";
    assert!(one(&format!("{base}methods = [\"CONNECT\"]")).is_err());
    assert!(one(&format!("{base}methods = [\"TRACE\"]")).is_err());
    for prefix in ["v1/", "/v1", "/v1/../", "/./v1/", "/v1%2F/", "/v1/?x/", "/v1\\\\/"] {
        let result = one(&format!("{base}path_prefixes = [{prefix:?}]"));
        assert!(result.is_err(), "prefix {prefix:?} must be rejected");
    }
    assert!(
        one(&format!("{base}unknown = 1")).is_err(),
        "unknown fields are rejected"
    );
}

#[test]
fn exact_host_matches_case_and_one_trailing_dot_only() {
    let binding = bearer("[\"api.example.com\"]");
    assert!(binding.matches_host("api.example.com"));
    assert!(binding.matches_host("API.EXAMPLE.COM"));
    assert!(binding.matches_host("api.example.com."));
    for host in [
        "example.com",
        "x.api.example.com",
        "api.example.com..",
        "api.example.com:443",
        "evil-api.example.com",
        "api.example.com.evil.test",
        "",
    ] {
        assert!(!binding.matches_host(host), "{host:?} must not match");
    }
}

#[test]
fn wildcard_matches_subdomains_on_label_boundary_not_apex() {
    let binding = bearer("[\"*.example.com\"]");
    assert!(binding.matches_host("a.example.com"));
    assert!(binding.matches_host("a.b.example.com"));
    assert!(binding.matches_host("A.Example.Com."));
    for host in [
        "example.com",
        "evil-example.com",
        "aexample.com",
        ".example.com",
        "example.com.evil.test",
        "a..example.com",
    ] {
        assert!(!binding.matches_host(host), "{host:?} must not match");
    }
}

#[test]
fn ip_literal_requests_never_match() {
    let binding = bearer("[\"*.example.com\"]");
    assert!(!binding.matches_host("127.0.0.1"));
    assert!(!binding.matches_host("[::1]"));
}

#[test]
fn request_limits_default_open_and_enforce_when_set() {
    let open = bearer("[\"a.example.com\"]");
    assert!(open.admits_request("DELETE", "/anything/%2e%2e/"));

    let limited = one(
        "hosts = [\"a.example.com\"]\nplacement = { query = \"k\" }\nmethods = [\"GET\"]\npath_prefixes = [\"/v1/\"]",
    )
    .unwrap();
    assert!(limited.admits_request("GET", "/v1/charges"));
    assert!(!limited.admits_request("POST", "/v1/charges"), "method outside limit");
    assert!(!limited.admits_request("get", "/v1/charges"), "methods compare exactly");
    for path in [
        "/v1",
        "/v10/charges",
        "/v2/charges",
        "/v1/../admin",
        "/v1/./x",
        "/v1/%2e%2e/admin",
        "/v1%2F..%2Fadmin",
        "/v1/\\..\\admin",
        "",
    ] {
        assert!(!limited.admits_request("GET", path), "{path:?} must be refused");
    }
}

#[test]
fn for_host_selects_matching_bindings_in_id_order() {
    let bindings = parse(
        r#"
[credential_bindings.zeta]
hosts = ["*.example.com"]
placement = { query = "k" }

[credential_bindings.alpha]
hosts = ["api.example.com"]
placement = { header = "x-api-key" }

[credential_bindings.other]
hosts = ["api.other.test"]
placement = { query = "k" }
"#,
    )
    .unwrap();
    let ids: Vec<_> = bindings.for_host("api.example.com").map(|(id, _)| id).collect();
    assert_eq!(ids, vec!["alpha", "zeta"]);
    assert_eq!(bindings.for_host("evil.test").count(), 0);
}
