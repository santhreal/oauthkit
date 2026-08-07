//! # oauthkit
//!
//! A provider-registry-driven OAuth SDK for command-line tools. It gives any CLI
//! the breadth of provider sign-in that model tools need (authorization-code with
//! PKCE, device-code, and API-key), without hard-coding a single provider.
//!
//! ## Design
//!
//! - **One data-driven registry.** Providers are declared as data
//!   ([`Registry`], backed by `rules/providers.toml`). A CLI extends the set by
//!   merging its own TOML, never by editing this crate.
//! - **Three flows, one token path.** [`flow::authorization_code`],
//!   [`flow::device_code`], and [`flow::api_key`] share one token-exchange and
//!   error-parsing path, so success/failure semantics live in one place.
//! - **UI-agnostic.** The SDK returns URLs, user codes, and [`Credential`]s. The
//!   CLI owns all rendering (its own look and feel).
//! - **Pluggable storage.** Persistence is a [`CredentialStore`] the CLI supplies.
//! - **No silent fallback.** Every flow fails loud: a state mismatch, an OAuth
//!   error, or a timeout returns an [`Error`], never a degraded success.
//!
//! ## Minimal usage
//!
//! ```no_run
//! # async fn run() -> oauthkit::Result<()> {
//! use oauthkit::{AuthClient, CredentialStore, MemoryStore};
//!
//! let client = AuthClient::builtin(MemoryStore::new())?;
//! for provider in client.providers() {
//!     println!("{} ({})", provider.display_name, provider.id);
//! }
//!
//! // API-key sign-in for a provider that offers it.
//! let credential = client.accept_api_key("anthropic", "sk-ant-...")?;
//! client.store().put(&credential)?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

/// The `README.md` examples are compiled (and where not `no_run`, executed) as
/// doctests, so the public API and its documentation cannot silently drift apart.
/// Compiled only under `cargo test`'s doctest pass; it is not part of the crate.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

mod credentials;
pub mod discovery;
#[cfg(feature = "encrypted-store")]
mod encrypted_store;
mod error;
pub mod flow;
mod pkce;
mod provider;

pub use credentials::Credential;
pub use credentials::CredentialKind;
pub use credentials::CredentialStore;
pub use credentials::MemoryStore;
pub use discovery::OidcMetadata;
pub use discovery::discover;
#[cfg(feature = "encrypted-store")]
pub use encrypted_store::EncryptedStore;
pub use error::Error;
pub use error::Result;
pub use flow::authorization_code::constant_time_eq;
pub use pkce::PkceCodes;
pub use pkce::generate_pkce;
pub use pkce::generate_state;
pub use provider::ApiKeyConfig;
pub use provider::AuthMethod;
pub use provider::DeviceCodeConfig;
pub use provider::OAuthConfig;
pub use provider::Provider;
pub use provider::Registry;

use std::time::Duration;

use crate::flow::authorization_code::BeganAuthorization;
use crate::flow::device_code::DeviceAuthorization;

/// A high-level facade binding a [`Registry`] to a [`CredentialStore`], plus the
/// flow entry points. A CLI can use this directly or drop down to [`flow`] and
/// [`Registry`] for finer control.
#[derive(Clone)]
pub struct AuthClient<S: CredentialStore> {
    registry: Registry,
    store: S,
}

impl<S: CredentialStore> AuthClient<S> {
    /// Build a client over the built-in provider registry.
    pub fn builtin(store: S) -> Result<Self> {
        Ok(Self {
            registry: Registry::builtin()?,
            store,
        })
    }

    /// Build a client over a caller-supplied registry (e.g. built-in merged with
    /// the CLI's own providers).
    pub fn new(registry: Registry, store: S) -> Self {
        Self { registry, store }
    }

    /// The provider registry.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// All providers, in presentation order.
    pub fn providers(&self) -> &[Provider] {
        self.registry.providers()
    }

    /// The credential store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Begin an authorization-code sign-in for a provider.
    pub fn begin_oauth(&self, provider_id: &str) -> Result<BeganAuthorization> {
        let provider = self.registry.require(provider_id)?;
        let config = provider.oauth().ok_or_else(|| Error::UnsupportedMethod {
            provider: provider_id.to_string(),
            method: "oauth",
        })?;
        flow::authorization_code::begin(provider_id, config)
    }

    /// Begin a device-code sign-in for a provider.
    pub async fn begin_device(&self, provider_id: &str) -> Result<DeviceAuthorization> {
        let provider = self.registry.require(provider_id)?;
        let config = provider.device().ok_or_else(|| Error::UnsupportedMethod {
            provider: provider_id.to_string(),
            method: "device",
        })?;
        flow::device_code::request(provider_id, config).await
    }

    /// Complete a device-code sign-in by polling the token endpoint until the
    /// user approves or `max_wait` elapses.
    pub async fn complete_device(
        &self,
        auth: DeviceAuthorization,
        max_wait: Duration,
    ) -> Result<Credential> {
        auth.poll(max_wait).await
    }

    /// Accept an API key for a provider (client-side shape check only).
    pub fn accept_api_key(&self, provider_id: &str, key: &str) -> Result<Credential> {
        let provider = self.registry.require(provider_id)?;
        let config = provider.api_key().ok_or_else(|| Error::UnsupportedMethod {
            provider: provider_id.to_string(),
            method: "api_key",
        })?;
        flow::api_key::accept(provider_id, config, key)
    }

    /// Read a provider's API key from its declared environment variable, if any.
    pub fn api_key_from_env(&self, provider_id: &str) -> Option<String> {
        let config = self.registry.get(provider_id)?.api_key()?;
        flow::api_key::from_env(config)
    }

    /// Refresh a stored OAuth credential whose access token is at/near expiry,
    /// persisting the result. Returns the fresh credential. Providers that reuse
    /// the existing refresh token keep it.
    pub async fn refresh_stored(&self, provider_id: &str) -> Result<Credential> {
        let provider = self.registry.require(provider_id)?;
        let config = provider.oauth().ok_or_else(|| Error::UnsupportedMethod {
            provider: provider_id.to_string(),
            method: "oauth",
        })?;
        let existing = self
            .store
            .get(provider_id)?
            .ok_or_else(|| Error::Store(format!("no stored credential for `{provider_id}`")))?;
        let refresh_token = existing
            .refresh_token()
            .cloned()
            .ok_or_else(|| Error::Store("stored credential has no refresh token".into()))?;

        let mut refreshed = flow::refresh(
            provider_id,
            &config.token_url,
            &config.client_id,
            &refresh_token,
        )
        .await?;
        if let (
            Credential::OAuth {
                refresh_token: new, ..
            },
            Some(old),
        ) = (&mut refreshed, existing.refresh_token())
        {
            if new.is_none() {
                *new = Some(old.clone());
            }
        }
        self.store.put(&refreshed)?;
        Ok(refreshed)
    }

    /// Sign out of a provider by deleting any stored credential.
    pub fn logout(&self, provider_id: &str) -> Result<()> {
        self.store.delete(provider_id)
    }
}

/// The SDK's default sign-in timeout for interactive flows.
pub const DEFAULT_SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests;
