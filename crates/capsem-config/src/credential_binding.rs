//! Host-declared credential bindings: the only destinations, placement and
//! request shape for which a brokered credential outside the built-in
//! providers may be materialized.
//!
//! A binding is trusted host configuration. Authority to substitute comes from
//! it (plus security-rule admission), never from the guest-held reference.
//! Every field is validated while deserializing, so an unvalidated binding is
//! unrepresentable and matching never re-checks configuration shape.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::validate_identifier;

const MAX_HOSTS: usize = 16;
const MAX_PATH_PREFIXES: usize = 32;
const MAX_FIELD_BYTES: usize = 128;
const MAX_HOST_BYTES: usize = 253;
const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
/// Headers that frame or route the request. Placing a secret in one would let
/// substitution change where or how the request is delivered.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
];

/// Validated bindings keyed by binding id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BTreeMap<String, CredentialBinding>")]
pub struct CredentialBindings(BTreeMap<String, CredentialBinding>);

impl TryFrom<BTreeMap<String, CredentialBinding>> for CredentialBindings {
    type Error = String;

    fn try_from(bindings: BTreeMap<String, CredentialBinding>) -> Result<Self, Self::Error> {
        for id in bindings.keys() {
            validate_identifier("credential binding id", id)?;
        }
        Ok(Self(bindings))
    }
}

impl CredentialBindings {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The user's bindings with corp's laid over them: a corp binding replaces
    /// the user's binding of the same id, so an admin can lock where a
    /// credential may go. Mirrors `McpConfig::merged` for servers.
    pub fn merged(user: &Self, corp: &Self) -> Self {
        let mut merged = user.0.clone();
        merged.extend(corp.0.iter().map(|(id, binding)| (id.clone(), binding.clone())));
        Self(merged)
    }

    pub fn get(&self, id: &str) -> Option<&CredentialBinding> {
        self.0.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &CredentialBinding)> {
        self.0.iter().map(|(id, binding)| (id.as_str(), binding))
    }

    /// Bindings whose host patterns match `host`, in id order.
    pub fn for_host<'a>(&'a self, host: &'a str) -> impl Iterator<Item = (&'a str, &'a CredentialBinding)> + 'a {
        self.iter().filter(move |(_, binding)| binding.matches_host(host))
    }
}

/// Where the reference must appear for it to be substituted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPlacement {
    /// A header, lowercased, optionally carrying `<scheme> <reference>`.
    Header { name: String, scheme: Option<String> },
    /// A query parameter key, compared exactly after percent-decoding.
    Query { key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCredentialBinding", into = "RawCredentialBinding")]
pub struct CredentialBinding {
    hosts: Vec<HostPattern>,
    placement: CredentialPlacement,
    methods: Vec<String>,
    path_prefixes: Vec<String>,
}

impl CredentialBinding {
    pub fn placement(&self) -> &CredentialPlacement {
        &self.placement
    }

    /// Each pattern's DNS name: the exact host, or the domain a `*.` wildcard
    /// covers. Lets callers reject bindings under domains they already own.
    pub fn host_names(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(|pattern| match pattern {
            HostPattern::Exact(exact) => exact.as_str(),
            HostPattern::Subdomains(suffix) => &suffix[1..],
        })
    }

    /// Exact host, or a `*.` wildcard matching any subdomain depth but not
    /// the apex. Case-insensitive; one trailing FQDN dot is ignored. Hosts
    /// with a port, IP literals and empty labels never match.
    pub fn matches_host(&self, host: &str) -> bool {
        let Some(host) = normalize_request_host(host) else {
            return false;
        };
        self.hosts.iter().any(|pattern| pattern.matches(&host))
    }

    /// True when method and path are within this binding's limits. An empty
    /// limit admits everything. With path prefixes configured, a path holding
    /// dot segments or encoded separators is refused outright: the upstream,
    /// not this check, would decide where it really points.
    pub fn admits_request(&self, method: &str, path: &str) -> bool {
        let method_ok = self.methods.is_empty() || self.methods.iter().any(|allowed| allowed == method);
        let path_ok = self.path_prefixes.is_empty()
            || (path_is_plain(path)
                && self
                    .path_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix.as_str())));
        method_ok && path_ok
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    Exact(String),
    /// Stored as `.example.com` so a suffix test is a label-boundary test.
    Subdomains(String),
}

impl HostPattern {
    fn parse(value: &str) -> Result<Self, String> {
        let host = value.trim().to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host);
        let (wildcard, name) = match host.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, host),
        };
        validate_dns_name(name).map_err(|reason| format!("credential binding host {value:?} {reason}"))?;
        if wildcard && !name.contains('.') {
            return Err(format!(
                "credential binding host {value:?} wildcard must cover at least two labels"
            ));
        }
        Ok(if wildcard {
            Self::Subdomains(format!(".{name}"))
        } else {
            Self::Exact(name.to_string())
        })
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(exact) => host == exact,
            Self::Subdomains(suffix) => host.len() > suffix.len() && host.ends_with(suffix.as_str()),
        }
    }

    fn as_config(&self) -> String {
        match self {
            Self::Exact(exact) => exact.clone(),
            Self::Subdomains(suffix) => format!("*{suffix}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredentialBinding {
    hosts: Vec<String>,
    placement: RawPlacement,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    path_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlacement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    query: Option<String>,
}

impl TryFrom<RawCredentialBinding> for CredentialBinding {
    type Error = String;

    fn try_from(raw: RawCredentialBinding) -> Result<Self, Self::Error> {
        if raw.hosts.is_empty() || raw.hosts.len() > MAX_HOSTS {
            return Err(format!("credential binding must declare 1 to {MAX_HOSTS} hosts"));
        }
        let hosts = raw
            .hosts
            .iter()
            .map(|host| HostPattern::parse(host))
            .collect::<Result<Vec<_>, _>>()?;
        let placement = parse_placement(raw.placement)?;
        let mut methods = Vec::with_capacity(raw.methods.len());
        for method in &raw.methods {
            let method = method.trim().to_ascii_uppercase();
            if !ALLOWED_METHODS.contains(&method.as_str()) {
                return Err(format!("credential binding method {method:?} is not supported"));
            }
            if !methods.contains(&method) {
                methods.push(method);
            }
        }
        if raw.path_prefixes.len() > MAX_PATH_PREFIXES {
            return Err(format!(
                "credential binding declares more than {MAX_PATH_PREFIXES} path prefixes"
            ));
        }
        for prefix in &raw.path_prefixes {
            if !prefix.starts_with('/')
                || !prefix.ends_with('/')
                || prefix.len() > MAX_FIELD_BYTES
                || !path_is_plain(prefix)
            {
                return Err(format!(
                    "credential binding path prefix {prefix:?} must start and end with '/' and hold no dot segments, encodings, query or fragment"
                ));
            }
        }
        Ok(Self {
            hosts,
            placement,
            methods,
            path_prefixes: raw.path_prefixes,
        })
    }
}

impl From<CredentialBinding> for RawCredentialBinding {
    fn from(binding: CredentialBinding) -> Self {
        let placement = match binding.placement {
            CredentialPlacement::Header { name, scheme } => RawPlacement {
                header: Some(name),
                scheme,
                query: None,
            },
            CredentialPlacement::Query { key } => RawPlacement {
                header: None,
                scheme: None,
                query: Some(key),
            },
        };
        Self {
            hosts: binding.hosts.iter().map(HostPattern::as_config).collect(),
            placement,
            methods: binding.methods,
            path_prefixes: binding.path_prefixes,
        }
    }
}

fn parse_placement(raw: RawPlacement) -> Result<CredentialPlacement, String> {
    match (raw.header, raw.query) {
        (Some(header), None) => {
            let name = header.trim().to_ascii_lowercase();
            if !is_token(&name) || name.len() > MAX_FIELD_BYTES {
                return Err(format!(
                    "credential binding header {header:?} is not a valid header name"
                ));
            }
            if RESERVED_HEADERS.contains(&name.as_str()) || name.starts_with("proxy-") {
                return Err(format!(
                    "credential binding header {name:?} frames or routes the request"
                ));
            }
            if let Some(scheme) = &raw.scheme {
                if !is_token(scheme) || scheme.len() > MAX_FIELD_BYTES {
                    return Err(format!("credential binding scheme {scheme:?} is not a valid token"));
                }
            }
            Ok(CredentialPlacement::Header {
                name,
                scheme: raw.scheme,
            })
        }
        (None, Some(key)) => {
            if raw.scheme.is_some() {
                return Err("credential binding scheme applies only to header placement".into());
            }
            if key.is_empty()
                || key.len() > MAX_FIELD_BYTES
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
            {
                return Err(format!(
                    "credential binding query key {key:?} must use only unreserved characters"
                ));
            }
            Ok(CredentialPlacement::Query { key })
        }
        _ => Err("credential binding placement must name exactly one of header or query".into()),
    }
}

fn validate_dns_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > MAX_HOST_BYTES {
        return Err("must be a DNS name of 1 to 253 characters");
    }
    if name.parse::<Ipv4Addr>().is_ok() || name.parse::<Ipv6Addr>().is_ok() || name.starts_with('[') {
        return Err("must not be an IP literal");
    }
    let labels_ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if !labels_ok {
        return Err("must be lowercase DNS labels without port, path or wildcard after the first label");
    }
    // A name whose last label is numeric is an IPv4 spelling such as
    // `127.1` or `0x7f.1` once resolvers are involved.
    if name
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("must not end in a numeric label");
    }
    Ok(())
}

fn normalize_request_host(host: &str) -> Option<String> {
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    validate_dns_name(host).ok()?;
    Some(host.to_string())
}

/// No dot segments, percent-encodings, backslashes, query or fragment, so a
/// byte prefix test means the same thing to us and to the upstream.
fn path_is_plain(path: &str) -> bool {
    !path.bytes().any(|b| matches!(b, b'%' | b'\\' | b'?' | b'#'))
        && !path.split('/').any(|segment| segment == "." || segment == "..")
}

/// RFC 9110 `token`.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests;
