//! Store namespaces: one per built-in provider, one per host-declared HTTP
//! credential binding.
//!
//! The namespace is the account key prefix and the reference hash domain, so
//! material injected for binding `a` is unreachable through binding `b` or a
//! built-in provider, even for the same raw value.

use std::borrow::Cow;

use crate::provider::credential_provider_from_str;
use crate::CredentialProvider;

const BINDING_PREFIX: &str = "http:";
const MAX_BINDING_ID_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CredentialNamespace {
    Provider(CredentialProvider),
    /// A validated binding id, matching `capsem_config::validate_identifier_shape`.
    Binding(String),
}

impl CredentialNamespace {
    pub fn binding(id: &str) -> Result<Self, String> {
        let valid = !id.is_empty()
            && id.len() <= MAX_BINDING_ID_BYTES
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
        if valid {
            Ok(Self::Binding(id.to_owned()))
        } else {
            Err("invalid credential binding id".into())
        }
    }

    /// Account prefix and reference domain: `anthropic`, `http:<binding>`.
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            Self::Provider(provider) => Cow::Borrowed(provider.as_str()),
            Self::Binding(id) => Cow::Owned(format!("{BINDING_PREFIX}{id}")),
        }
    }

    pub(crate) fn account(&self, credential_ref: &str) -> String {
        format!("{}:{credential_ref}", self.as_str())
    }

    /// Inverse of [`Self::as_str`]; `None` for anything this build does not own.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.strip_prefix(BINDING_PREFIX) {
            Some(id) => Self::binding(id).ok(),
            None => credential_provider_from_str(value).map(Self::Provider),
        }
    }

    /// Split `<namespace>:<reference>`. References contain `:` themselves, so a
    /// binding account is split after its second separator, not its first.
    pub(crate) fn parse_account(account: &str) -> Option<(Self, &str)> {
        let split = match account.strip_prefix(BINDING_PREFIX) {
            Some(rest) => BINDING_PREFIX.len() + rest.find(':')?,
            None => account.find(':')?,
        };
        let (namespace, credential_ref) = (&account[..split], &account[split + 1..]);
        Some((Self::parse(namespace)?, credential_ref))
    }
}

impl From<CredentialProvider> for CredentialNamespace {
    fn from(provider: CredentialProvider) -> Self {
        Self::Provider(provider)
    }
}

#[cfg(test)]
mod tests;
