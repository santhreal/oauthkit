//! The provider registry: declarative, data-driven descriptions of how to sign
//! into each provider. This is the single source of truth for provider breadth.
//!
//! A CLI extends the set purely as data: drop a TOML table into its own registry
//! file, no code change. The built-in registry ([`Registry::builtin`]) ships the
//! common model providers.

use serde::Deserialize;
use serde::Serialize;
use url::Url;

use crate::error::Error;
use crate::error::Result;

/// The bundled provider registry data (Tier-B). A CLI may append its own.
const BUILTIN_REGISTRY_TOML: &str = include_str!("../rules/providers.toml");

/// One authentication method a provider offers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "flow", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Browser authorization-code flow with PKCE and a loopback redirect.
    Oauth(OAuthConfig),
    /// Device-code flow for headless/remote environments.
    Device(DeviceCodeConfig),
    /// A raw API key the user pastes in.
    ApiKey(ApiKeyConfig),
}

impl AuthMethod {
    /// A short, stable machine name for the method (for errors, telemetry, UI keys).
    pub fn kind(&self) -> &'static str {
        match self {
            AuthMethod::Oauth(_) => "oauth",
            AuthMethod::Device(_) => "device",
            AuthMethod::ApiKey(_) => "api_key",
        }
    }

    /// A one-line label a picker can render for this method.
    pub fn label(&self) -> &str {
        match self {
            AuthMethod::Oauth(c) => c.label.as_deref().unwrap_or("Sign in with browser"),
            AuthMethod::Device(c) => c.label.as_deref().unwrap_or("Sign in with a device code"),
            AuthMethod::ApiKey(c) => c.label.as_deref().unwrap_or("Paste an API key"),
        }
    }
}

/// Configuration for an authorization-code + PKCE OAuth flow.
///
/// This type is `#[non_exhaustive]`: new provider knobs are added over time as
/// compatible (patch) releases, so construct it with [`OAuthConfig::new`] and
/// then set the optional fields you need, rather than a struct literal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OAuthConfig {
    /// The authorization endpoint (front-channel, opened in the browser).
    pub authorize_url: String,
    /// The token endpoint (back-channel exchange and refresh).
    pub token_url: String,
    /// The public OAuth client id.
    pub client_id: String,
    /// Requested scopes.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Fixed redirect URI, if the provider requires an exact registered value
    /// rather than a dynamic `http://127.0.0.1:<port>/callback` loopback.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Fixed loopback port to request. When unset the SDK binds an ephemeral port.
    #[serde(default)]
    pub loopback_port: Option<u16>,
    /// OAuth `audience` (RFC 8707 / Auth0-style API identifier). When set it is
    /// added to the authorize URL as `audience=<value>`.
    #[serde(default)]
    pub audience: Option<String>,
    /// OpenID Connect `prompt` value (e.g. `login`, `consent`, `select_account`).
    /// When set it is added to the authorize URL as `prompt=<value>`.
    #[serde(default)]
    pub prompt: Option<String>,
    /// OpenID Connect `login_hint` (a pre-filled account identifier). When set it
    /// is added to the authorize URL as `login_hint=<value>`.
    #[serde(default)]
    pub login_hint: Option<String>,
    /// Extra static query parameters to add to the authorize URL, for provider
    /// -specific toggles not covered by a typed field above. Prefer the typed
    /// [`audience`](Self::audience) / [`prompt`](Self::prompt) /
    /// [`login_hint`](Self::login_hint) fields for those well-known parameters; a
    /// custom key here that collides with a parameter oauthkit already emits
    /// (including a typed field) is dropped to avoid a duplicate query key.
    #[serde(default)]
    pub extra_authorize_params: Vec<(String, String)>,
    /// Optional human label for a picker.
    #[serde(default)]
    pub label: Option<String>,
}

impl OAuthConfig {
    /// Build a config from the three required endpoints/ids, defaulting every
    /// optional field. Set the optional fields (`scopes`, `audience`, `prompt`,
    /// `login_hint`, `redirect_uri`, `loopback_port`, `extra_authorize_params`,
    /// `label`) on the returned value as needed.
    pub fn new(
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            client_id: client_id.into(),
            ..Self::default()
        }
    }
}

/// Configuration for a device-code (RFC 8628) flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCodeConfig {
    /// The device-authorization endpoint.
    pub device_authorization_url: String,
    /// The token endpoint that is polled for completion.
    pub token_url: String,
    /// The public OAuth client id.
    pub client_id: String,
    /// Requested scopes.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional human label for a picker.
    #[serde(default)]
    pub label: Option<String>,
}

/// Configuration for API-key sign-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// The environment variable a CLI reads to pick the key up non-interactively.
    #[serde(default)]
    pub env_var: Option<String>,
    /// A console/dashboard URL to show the user where to mint a key.
    #[serde(default)]
    pub console_url: Option<String>,
    /// A prefix the key is expected to start with (a cheap client-side sanity
    /// check, never a substitute for server validation).
    #[serde(default)]
    pub key_prefix: Option<String>,
    /// Optional human label for a picker.
    #[serde(default)]
    pub label: Option<String>,
}

/// A single sign-in-able provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    /// Stable machine id (e.g. `anthropic`, `openai`, `github-copilot`).
    pub id: String,
    /// Human display name (e.g. `Anthropic`, `OpenAI`, `GitHub Copilot`).
    pub display_name: String,
    /// The auth methods this provider offers, in the order to present them.
    pub methods: Vec<AuthMethod>,
    /// A short catalog note (optional), e.g. plan or region.
    #[serde(default)]
    pub note: Option<String>,
}

impl Provider {
    /// The first OAuth (authorization-code) method, if any.
    pub fn oauth(&self) -> Option<&OAuthConfig> {
        self.methods.iter().find_map(|m| match m {
            AuthMethod::Oauth(c) => Some(c),
            _ => None,
        })
    }

    /// The first device-code method, if any.
    pub fn device(&self) -> Option<&DeviceCodeConfig> {
        self.methods.iter().find_map(|m| match m {
            AuthMethod::Device(c) => Some(c),
            _ => None,
        })
    }

    /// The first API-key method, if any.
    pub fn api_key(&self) -> Option<&ApiKeyConfig> {
        self.methods.iter().find_map(|m| match m {
            AuthMethod::ApiKey(c) => Some(c),
            _ => None,
        })
    }
}

/// The set of known providers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    /// Providers keyed by presentation order.
    #[serde(default, rename = "provider")]
    providers: Vec<Provider>,
}

impl Registry {
    /// Load the built-in provider set that ships with the SDK.
    pub fn builtin() -> Result<Self> {
        Self::from_toml(BUILTIN_REGISTRY_TOML)
    }

    /// Parse a registry from TOML.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let registry: Registry =
            toml::from_str(toml_str).map_err(|e| Error::Registry(e.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }

    /// Merge another registry's providers into this one. A later provider with an
    /// existing id replaces the earlier one (so a CLI's own file overrides a
    /// built-in), keeping the ordering of first appearance.
    pub fn merge(&mut self, other: Registry) {
        for provider in other.providers {
            if let Some(existing) = self.providers.iter_mut().find(|p| p.id == provider.id) {
                *existing = provider;
            } else {
                self.providers.push(provider);
            }
        }
    }

    /// All providers, in presentation order.
    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    /// Look up one provider by id.
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id == id)
    }

    /// Look up one provider by id, or error with [`Error::UnknownProvider`].
    pub fn require(&self, id: &str) -> Result<&Provider> {
        self.get(id)
            .ok_or_else(|| Error::UnknownProvider(id.to_string()))
    }

    /// Reject structurally invalid registries early (duplicate ids, empty methods,
    /// blank required OAuth fields) so a consuming CLI never routes a user into a
    /// half-defined flow.
    fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for provider in &self.providers {
            if provider.id.trim().is_empty() {
                return Err(Error::Registry("a provider has an empty id".into()));
            }
            if !seen.insert(provider.id.as_str()) {
                return Err(Error::Registry(format!(
                    "duplicate provider id `{}`",
                    provider.id
                )));
            }
            if provider.methods.is_empty() {
                return Err(Error::Registry(format!(
                    "provider `{}` defines no auth methods",
                    provider.id
                )));
            }
            let mut seen_kinds = std::collections::BTreeSet::new();
            for method in &provider.methods {
                let kind = method.kind();
                if !seen_kinds.insert(kind) {
                    return Err(Error::Registry(format!(
                        "provider `{}` defines more than one `{}` method",
                        provider.id, kind
                    )));
                }
                match method {
                    AuthMethod::Oauth(c) => {
                        if c.authorize_url.is_empty()
                            || c.token_url.is_empty()
                            || c.client_id.is_empty()
                        {
                            return Err(Error::Registry(format!(
                                "provider `{}` oauth method is missing authorize_url/token_url/client_id",
                                provider.id
                            )));
                        }
                        validate_url(&c.authorize_url, &provider.id, "authorize_url")?;
                        validate_url(&c.token_url, &provider.id, "token_url")?;
                        if c.redirect_uri.is_some() && c.loopback_port.is_some() {
                            return Err(Error::Registry(format!(
                                "provider `{}` oauth method sets both redirect_uri and loopback_port",
                                provider.id
                            )));
                        }
                        if let Some(redirect_uri) = &c.redirect_uri {
                            validate_loopback_redirect_uri(redirect_uri, &provider.id)?;
                        }
                    }
                    AuthMethod::Device(c) => {
                        if c.device_authorization_url.is_empty()
                            || c.token_url.is_empty()
                            || c.client_id.is_empty()
                        {
                            return Err(Error::Registry(format!(
                                "provider `{}` device method is missing device_authorization_url/token_url/client_id",
                                provider.id
                            )));
                        }
                        validate_url(
                            &c.device_authorization_url,
                            &provider.id,
                            "device_authorization_url",
                        )?;
                        validate_url(&c.token_url, &provider.id, "token_url")?;
                    }
                    AuthMethod::ApiKey(_) => {}
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_url(url: &str, provider_id: &str, field: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|e| {
        Error::Registry(format!(
            "provider `{provider_id}` {field} is not a valid URL: {e}"
        ))
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(Error::Registry(format!(
            "provider `{provider_id}` {field} must use http or https, got `{}`",
            parsed.scheme()
        )));
    }
    // Tokens and authorization codes cross these endpoints, so TLS is mandatory
    // (CWE-319). Plain http is allowed only to loopback hosts, the documented
    // pattern for local provider development and in-process test servers.
    if parsed.scheme() == "http" {
        match parsed.host_str() {
            Some("127.0.0.1" | "localhost" | "::1") => {}
            other => {
                return Err(Error::Registry(format!(
                    "provider `{provider_id}` {field} must use https (http is allowed only to loopback hosts, got {other:?})"
                )));
            }
        }
    }
    Ok(())
}

fn validate_loopback_redirect_uri(redirect_uri: &str, provider_id: &str) -> Result<()> {
    let parsed = Url::parse(redirect_uri).map_err(|e| {
        Error::Registry(format!(
            "provider `{provider_id}` redirect_uri is not a valid URL: {e}"
        ))
    })?;
    if parsed.scheme() != "http" {
        return Err(Error::Registry(format!(
            "provider `{provider_id}` redirect_uri must use http, got `{}`",
            parsed.scheme()
        )));
    }
    match parsed.host_str() {
        Some("127.0.0.1") | Some("localhost") | Some("::1") | Some("[::1]") => {}
        other => {
            return Err(Error::Registry(format!(
                "provider `{provider_id}` redirect_uri must point to 127.0.0.1, localhost, or [::1], got {other:?}"
            )));
        }
    }
    if parsed.port().is_none() {
        return Err(Error::Registry(format!(
            "provider `{provider_id}` redirect_uri must include an explicit port"
        )));
    }
    Ok(())
}
