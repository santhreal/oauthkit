//! OpenID Connect discovery.
//!
//! Many OIDC providers publish their endpoints at
//! `<issuer>/.well-known/openid-configuration` (OpenID Connect Discovery 1.0 §4).
//! [`discover`] fetches and validates that document so a caller can build an
//! [`OAuthConfig`] from it instead of hand-copying endpoint URLs.
//!
//! The caller still owns client identity: discovery supplies *endpoints*, and the
//! caller supplies the `client_id` and scopes via [`OidcMetadata::to_oauth_config`].

use serde::Deserialize;

use crate::error::Error;
use crate::error::Result;
use crate::flow::http_client;
use crate::provider::OAuthConfig;

/// The path appended to an issuer to reach its discovery document (OIDC
/// Discovery 1.0 §4).
const WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";

/// The subset of the OpenID Provider Metadata document (OIDC Discovery §3) that
/// `oauthkit` consumes. Unknown fields are ignored so a provider's extra metadata
/// does not break parsing.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct OidcMetadata {
    /// The issuer identifier. Discovery §4.3 requires it to equal the issuer the
    /// document was fetched for; [`discover`] enforces that.
    pub issuer: String,
    /// The authorization endpoint (front-channel).
    pub authorization_endpoint: String,
    /// The token endpoint (back-channel exchange/refresh).
    pub token_endpoint: String,
    /// The device-authorization endpoint (RFC 8628), when the provider offers it.
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    /// The token-revocation endpoint (RFC 7009), when advertised.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// Scopes the provider advertises support for, when present.
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    /// PKCE code-challenge methods the provider supports, when present.
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

impl OidcMetadata {
    /// Build an authorization-code [`OAuthConfig`] from the discovered endpoints
    /// plus a caller-supplied `client_id` and `scopes`. Loopback/redirect and the
    /// typed authorize parameters keep their defaults; set them on the returned
    /// config if the provider needs them.
    pub fn to_oauth_config(
        &self,
        client_id: impl Into<String>,
        scopes: Vec<String>,
    ) -> OAuthConfig {
        OAuthConfig {
            scopes,
            ..OAuthConfig::new(
                self.authorization_endpoint.clone(),
                self.token_endpoint.clone(),
                client_id,
            )
        }
    }
}

/// Fetch and validate the OIDC discovery document for `issuer`.
///
/// The document is fetched from `<issuer>/.well-known/openid-configuration`; a
/// trailing slash on `issuer` is normalized so the path is never doubled. The
/// call fails loud on a non-2xx status, a body that is not valid metadata, or an
/// `issuer` in the document that does not match the requested one (Discovery §4.3,
/// a mix-up defense). It never returns a partial or guessed configuration.
#[tracing::instrument(level = "debug", skip_all, fields(issuer = %issuer))]
pub async fn discover(issuer: &str) -> Result<OidcMetadata> {
    let base = issuer.trim_end_matches('/');
    let url = format!("{base}{WELL_KNOWN_PATH}");
    tracing::debug!("fetching OIDC discovery document");

    let client = http_client()?;
    let response = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        tracing::warn!(status = %status, "OIDC discovery endpoint returned a non-success status");
        return Err(Error::Authorization(format!(
            "OIDC discovery failed: HTTP {status}"
        )));
    }

    let metadata: OidcMetadata = serde_json::from_str(&body)
        .map_err(|e| Error::Malformed(format!("OIDC discovery document: {e}")))?;

    // Discovery §4.3: the returned issuer MUST equal the requested issuer.
    if metadata.issuer.trim_end_matches('/') != base {
        return Err(Error::Malformed(format!(
            "OIDC issuer mismatch: requested `{base}`, document declares `{}`",
            metadata.issuer
        )));
    }

    tracing::debug!(
        has_device = metadata.device_authorization_endpoint.is_some(),
        "OIDC discovery succeeded"
    );
    Ok(metadata)
}
