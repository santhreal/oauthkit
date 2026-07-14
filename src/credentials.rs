//! The credential a sign-in produces, and the pluggable store that persists it.

use serde::Deserialize;
use serde::Serialize;

use crate::error::Result;

/// The material a completed sign-in yields for one provider.
///
/// A flow produces exactly one of the two shapes: an OAuth grant (access token,
/// optional refresh token and expiry) or a raw API key. The enum guarantees the
/// two shapes are mutually exclusive: an OAuth credential never carries an
/// `api_key`, and an API-key credential never carries tokens.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credential {
    /// Authorization-code + PKCE or device-code OAuth grant.
    OAuth {
        /// The provider id these credentials authenticate.
        provider: String,
        /// OAuth access token.
        access_token: String,
        /// OAuth refresh token, when the grant is refreshable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        /// Absolute Unix expiry (seconds) of `access_token`, when the server gave one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at_unix: Option<i64>,
        /// The OAuth token type, typically `Bearer`. RFC 6749 §5.1 requires this in
        /// token responses; it is stored as optional so older serialized credentials
        /// without it still load, but new grants always set it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_type: Option<String>,
        /// Optional account label the provider returned (email, org, plan).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_label: Option<String>,
    },
    /// A raw provider API key.
    ApiKey {
        /// The provider id these credentials authenticate.
        provider: String,
        /// Raw API key.
        api_key: String,
        /// Optional account label the provider returned (email, org, plan).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_label: Option<String>,
    },
}

/// Which flow minted a [`Credential`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Authorization-code + PKCE or device-code OAuth grant.
    OAuth,
    /// A raw provider API key.
    ApiKey,
}

impl Credential {
    /// Build an OAuth credential from a token response.
    pub fn oauth(
        provider: impl Into<String>,
        access_token: String,
        refresh_token: Option<String>,
        expires_at_unix: Option<i64>,
        token_type: Option<String>,
    ) -> Self {
        Self::OAuth {
            provider: provider.into(),
            access_token,
            refresh_token,
            expires_at_unix,
            token_type,
            account_label: None,
        }
    }

    /// Build an API-key credential.
    pub fn api_key(provider: impl Into<String>, api_key: String) -> Self {
        Self::ApiKey {
            provider: provider.into(),
            api_key,
            account_label: None,
        }
    }

    /// Which flow minted this credential.
    pub fn kind(&self) -> CredentialKind {
        match self {
            Self::OAuth { .. } => CredentialKind::OAuth,
            Self::ApiKey { .. } => CredentialKind::ApiKey,
        }
    }

    /// The provider id these credentials authenticate.
    pub fn provider(&self) -> &str {
        match self {
            Self::OAuth { provider, .. } | Self::ApiKey { provider, .. } => provider.as_str(),
        }
    }

    /// The OAuth access token, if this is an OAuth grant.
    pub fn access_token(&self) -> Option<&String> {
        match self {
            Self::OAuth { access_token, .. } => Some(access_token),
            Self::ApiKey { .. } => None,
        }
    }

    /// The OAuth refresh token, if this is an OAuth grant and the server gave one.
    pub fn refresh_token(&self) -> Option<&String> {
        match self {
            Self::OAuth { refresh_token, .. } => refresh_token.as_ref(),
            Self::ApiKey { .. } => None,
        }
    }

    /// The raw API key, if this is an API-key credential.
    pub fn api_key_value(&self) -> Option<&String> {
        match self {
            Self::ApiKey { api_key, .. } => Some(api_key),
            Self::OAuth { .. } => None,
        }
    }

    /// Absolute Unix expiry of an OAuth access token, if the server gave one.
    pub fn expires_at_unix(&self) -> Option<i64> {
        match self {
            Self::OAuth {
                expires_at_unix, ..
            } => *expires_at_unix,
            Self::ApiKey { .. } => None,
        }
    }

    /// The OAuth token type, typically `Bearer`.
    pub fn token_type(&self) -> Option<&String> {
        match self {
            Self::OAuth { token_type, .. } => token_type.as_ref(),
            Self::ApiKey { .. } => None,
        }
    }

    /// Optional account label the provider returned (email, org, plan).
    pub fn account_label(&self) -> Option<&str> {
        match self {
            Self::OAuth { account_label, .. } | Self::ApiKey { account_label, .. } => {
                account_label.as_deref()
            }
        }
    }

    /// Attach a human-readable account label (chainable).
    #[must_use]
    pub fn with_account_label(self, label: impl Into<String>) -> Self {
        let label = label.into();
        let mut this = self;
        match &mut this {
            Self::OAuth { account_label, .. } | Self::ApiKey { account_label, .. } => {
                *account_label = Some(label);
            }
        }
        this
    }

    /// Whether an OAuth access token is at or past its expiry, given the current
    /// Unix time. API keys and expiry-less grants never report expired.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        match self {
            Self::OAuth {
                expires_at_unix, ..
            } => expires_at_unix.is_some_and(|exp| now_unix >= exp),
            Self::ApiKey { .. } => false,
        }
    }

    /// The bearer/api value a caller should present, whichever this credential holds.
    pub fn secret(&self) -> Option<&str> {
        match self {
            Self::OAuth { access_token, .. } => Some(access_token.as_str()),
            Self::ApiKey { api_key, .. } => Some(api_key.as_str()),
        }
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the tokens/keys themselves (CWE-532).
        match self {
            Self::OAuth {
                provider,
                access_token: _,
                refresh_token,
                expires_at_unix,
                token_type,
                account_label,
            } => f
                .debug_struct("Credential")
                .field("provider", provider)
                .field("kind", &CredentialKind::OAuth)
                .field("access_token", &Some::<&str>("<redacted>"))
                .field(
                    "refresh_token",
                    &refresh_token.as_ref().map(|_| "<redacted>"),
                )
                .field("api_key", &None::<&str>)
                .field("expires_at_unix", expires_at_unix)
                .field("token_type", token_type)
                .field("account_label", account_label)
                .finish(),
            Self::ApiKey {
                provider,
                api_key: _,
                account_label,
            } => f
                .debug_struct("Credential")
                .field("provider", provider)
                .field("kind", &CredentialKind::ApiKey)
                .field("access_token", &None::<&str>)
                .field("refresh_token", &None::<&str>)
                .field("api_key", &Some::<&str>("<redacted>"))
                .field("expires_at_unix", &None::<i64>)
                .field("token_type", &None::<&str>)
                .field("account_label", account_label)
                .finish(),
        }
    }
}

/// A pluggable persistence backend for credentials.
///
/// The SDK never dictates where secrets live: a CLI plugs in a keyring, an
/// encrypted file, or an in-memory store for tests. Implementations must not log
/// the credentials they persist.
pub trait CredentialStore: Send + Sync {
    /// Persist (overwriting any prior credential for the same provider).
    fn put(&self, credential: &Credential) -> Result<()>;
    /// Load the stored credential for a provider, if any.
    fn get(&self, provider: &str) -> Result<Option<Credential>>;
    /// Remove any stored credential for a provider. Idempotent.
    fn delete(&self, provider: &str) -> Result<()>;
    /// List the providers that currently have a stored credential.
    fn providers(&self) -> Result<Vec<String>>;
}

/// A process-lifetime, thread-safe in-memory store. Handy for tests and for CLIs
/// that manage their own persistence and only need the SDK's flow orchestration.
#[derive(Default)]
pub struct MemoryStore {
    inner: std::sync::RwLock<std::collections::BTreeMap<String, Credential>>,
}

impl Clone for MemoryStore {
    fn clone(&self) -> Self {
        let map = match self.inner.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Self {
            inner: std::sync::RwLock::new(map),
        }
    }
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialStore for MemoryStore {
    fn put(&self, credential: &Credential) -> Result<()> {
        self.inner
            .write()
            .map_err(|_| crate::error::Error::Store("memory store lock poisoned".into()))?
            .insert(credential.provider().to_string(), credential.clone());
        Ok(())
    }

    fn get(&self, provider: &str) -> Result<Option<Credential>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| crate::error::Error::Store("memory store lock poisoned".into()))?
            .get(provider)
            .cloned())
    }

    fn delete(&self, provider: &str) -> Result<()> {
        self.inner
            .write()
            .map_err(|_| crate::error::Error::Store("memory store lock poisoned".into()))?
            .remove(provider);
        Ok(())
    }

    fn providers(&self) -> Result<Vec<String>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| crate::error::Error::Store("memory store lock poisoned".into()))?
            .keys()
            .cloned()
            .collect())
    }
}
