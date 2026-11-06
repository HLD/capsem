//! Substitution for host-declared HTTP credential bindings.
//!
//! Reached only when the destination has no built-in provider and at least
//! one binding names its host. Authority comes from the binding: the host, the
//! exact header or query key holding the reference, and the method and path
//! limits. A reference found anywhere else is refused, never forwarded, and a
//! reference issued for one binding cannot resolve through another because the
//! store keys material by binding.

use capsem_config::{CredentialBinding, CredentialBindings, CredentialPlacement};

use super::{
    is_broker_reference, percent_decode, percent_encode_query_value, BrokeredUpstreamCredentials, UpstreamTarget,
};

/// Looks up material for `(binding id, reference)`. Absent and unreadable
/// are the same answer: the reference is refused, never forwarded.
pub(super) type BoundResolver<'r> = dyn Fn(&str, &str) -> Option<String> + 'r;

const REFUSED: &str = "credential binding refused: reference is outside every binding admitted for this request";

/// `Ok(None)` when no binding names the host, so the caller keeps the
/// built-in path's fail-closed behavior for unbound destinations.
pub(super) fn substitute_bound(
    target: UpstreamTarget<'_>,
    bindings: &CredentialBindings,
    resolve: &BoundResolver<'_>,
    headers: &mut http::HeaderMap,
    query: Option<&str>,
) -> Result<Option<BrokeredUpstreamCredentials>, String> {
    let named: Vec<(&str, &CredentialBinding)> = bindings.for_host(target.domain).collect();
    if named.is_empty() {
        return Ok(None);
    }
    // A request without method or path facts cannot be checked against
    // limits, so it is admitted by no binding rather than by every binding.
    let admitted: Vec<(&str, &CredentialBinding)> = if target.method.is_empty() || target.path.is_empty() {
        Vec::new()
    } else {
        named
            .into_iter()
            .filter(|(_, binding)| binding.admits_request(target.method, target.path))
            .collect()
    };
    let mut credential_ref = None;

    for (name, value) in headers.iter_mut() {
        let text = value
            .to_str()
            .map_err(|e| format!("broker reference header is not UTF-8: {e}"))?;
        let Some((scheme, reference)) = header_reference(text) else {
            continue;
        };
        let raw = resolve_admitted(&admitted, resolve, reference, |placement| match placement {
            CredentialPlacement::Header {
                name: bound_name,
                scheme: bound_scheme,
            } => {
                bound_name == name.as_str()
                    && match (bound_scheme, scheme) {
                        (None, None) => true,
                        (Some(bound), Some(sent)) => bound.eq_ignore_ascii_case(sent),
                        _ => false,
                    }
            }
            CredentialPlacement::Query { .. } => false,
        })?;
        credential_ref.get_or_insert_with(|| reference.to_string());
        let substituted = match scheme {
            Some(scheme) => format!("{scheme} {raw}"),
            None => raw,
        };
        *value = http::HeaderValue::from_str(&substituted)
            .map_err(|e| format!("stored credential is not valid header value: {e}"))?;
    }

    let query = match query {
        Some(query) => Some(substitute_bound_query(query, &admitted, resolve, &mut credential_ref)?),
        None => None,
    };
    Ok(Some(BrokeredUpstreamCredentials { credential_ref, query }))
}

fn substitute_bound_query(
    query: &str,
    admitted: &[(&str, &CredentialBinding)],
    resolve: &BoundResolver<'_>,
    credential_ref: &mut Option<String>,
) -> Result<String, String> {
    let mut changed = false;
    let mut parts = Vec::new();
    for part in query.split('&') {
        let Some((key, value)) = part.split_once('=') else {
            parts.push(part.to_string());
            continue;
        };
        let decoded = percent_decode(value)?;
        if !is_broker_reference(&decoded) {
            parts.push(part.to_string());
            continue;
        }
        let raw = resolve_admitted(
            admitted,
            resolve,
            &decoded,
            |placement| matches!(placement, CredentialPlacement::Query { key: bound } if bound == key),
        )?;
        credential_ref.get_or_insert(decoded);
        parts.push(format!("{key}={}", percent_encode_query_value(&raw)));
        changed = true;
    }
    Ok(if changed { parts.join("&") } else { query.to_string() })
}

/// The first admitted binding, in id order, whose placement matches and
/// which holds material for `reference`. Anything else is a refusal.
fn resolve_admitted(
    admitted: &[(&str, &CredentialBinding)],
    resolve: &BoundResolver<'_>,
    reference: &str,
    placed: impl Fn(&CredentialPlacement) -> bool,
) -> Result<String, String> {
    for (id, binding) in admitted {
        if !placed(binding.placement()) {
            continue;
        }
        if let Some(raw) = resolve(id, reference) {
            return Ok(raw);
        }
    }
    Err(REFUSED.to_string())
}

/// `<reference>` or `<scheme> <reference>` with a single-token scheme.
fn header_reference(value: &str) -> Option<(Option<&str>, &str)> {
    let trimmed = value.trim();
    if is_broker_reference(trimmed) {
        return Some((None, trimmed));
    }
    let (scheme, reference) = trimmed.split_once(' ')?;
    (!scheme.is_empty() && is_broker_reference(reference)).then_some((Some(scheme), reference))
}

#[cfg(test)]
mod tests;
