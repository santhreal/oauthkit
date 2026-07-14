//! The three sign-in flows and the token machinery they share.

pub mod api_key;
pub mod authorization_code;
pub mod device_code;

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;

use crate::credentials::Credential;
use crate::error::Error;
use crate::error::Result;

/// The `User-Agent` the SDK presents on token requests. A CLI may override it via
/// [`http_client_with_user_agent`].
pub const DEFAULT_USER_AGENT: &str = concat!("oauthkit/", env!("CARGO_PKG_VERSION"));

/// Default per-request timeout for HTTP calls to provider endpoints.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default time to wait for a TCP connection before giving up.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A standard OAuth 2.0 token endpoint response (RFC 6749 §5.1).
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// RFC 6749 §5.1 lists `token_type` as required. A response that omits it
    /// is non-conforming and is rejected as malformed.
    pub token_type: String,
}

/// A standard OAuth 2.0 error response (RFC 6749 §5.2).
#[derive(Debug, Deserialize)]
pub(crate) struct TokenErrorResponse {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Build the default HTTP client used for token requests.
pub fn http_client() -> Result<reqwest::Client> {
    http_client_with_user_agent(DEFAULT_USER_AGENT)
}

/// Build an HTTP client with a caller-chosen `User-Agent` (some providers key
/// behaviour off it).
pub fn http_client_with_user_agent(user_agent: &str) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(DEFAULT_TIMEOUT)
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .build()
        .map_err(Error::from)
}

/// Turn `expires_in` seconds into an absolute Unix expiry, relative to now.
pub(crate) fn expiry_from_expires_in(expires_in: Option<i64>) -> Option<i64> {
    let expires_in = expires_in?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Some(now + expires_in)
}

/// Try to parse an OAuth error body into a short, safe detail string.
///
/// Error bodies are expected to contain codes and descriptions, not tokens, so
/// the resulting string is safe to include in an error message.
pub(crate) fn oauth_error_detail(body: &str) -> Option<String> {
    serde_json::from_str::<TokenErrorResponse>(body)
        .ok()
        .map(|err| match err.error_description {
            Some(desc) => format!("{}: {desc}", err.error),
            None => err.error,
        })
}

/// POST a form to a token endpoint and parse the grant into a [`Credential`].
///
/// Shared by the authorization-code, device-code, and refresh paths so the
/// success/error parsing lives in exactly one place.
// `skip_all` is deliberate: the `form` argument carries the authorization code
// and/or refresh token, so it must never reach a span field. Only the provider id
// and (public) token endpoint are recorded.
#[tracing::instrument(level = "debug", skip_all, fields(provider = %provider, token_url = %token_url))]
pub(crate) async fn post_token_form(
    client: &reqwest::Client,
    provider: &str,
    token_url: &str,
    form: &[(&str, &str)],
) -> Result<Credential> {
    tracing::debug!("posting token form to endpoint");
    let response = client
        .post(token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        // Prefer the structured OAuth error; fall back to the raw status, but never
        // include anything that could be a token (error bodies are error codes).
        if let Some(detail) = oauth_error_detail(&body) {
            tracing::warn!(status = %status, error = %detail, "token endpoint returned an OAuth error");
            return Err(Error::Authorization(detail));
        }
        tracing::warn!(status = %status, "token endpoint returned a non-success status");
        return Err(Error::Authorization(format!("HTTP {status}")));
    }

    let token: TokenResponse = serde_json::from_str(&body).map_err(|e| {
        tracing::warn!("token response was not valid JSON");
        Error::Malformed(format!("token response was not valid JSON: {e}"))
    })?;

    // Record only shape, never the token material.
    tracing::debug!(
        has_refresh = token.refresh_token.is_some(),
        has_expiry = token.expires_in.is_some(),
        "token exchange succeeded"
    );
    Ok(Credential::oauth(
        provider.to_string(),
        token.access_token,
        token.refresh_token,
        expiry_from_expires_in(token.expires_in),
        Some(token.token_type),
    ))
}

/// Exchange a refresh token for a fresh access token at `token_url`.
///
/// Providers that omit a new `refresh_token` on refresh keep the caller's
/// existing one (the returned credential carries `None`, and the caller merges).
// `refresh_token` is a secret and is excluded from the span; `client_id` is a
// public OAuth parameter and is safe to record.
#[tracing::instrument(level = "debug", skip_all, fields(provider = %provider, client_id = %client_id))]
pub async fn refresh(
    provider: &str,
    token_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<Credential> {
    tracing::debug!("refreshing access token");
    let client = http_client()?;
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    post_token_form(&client, provider, token_url, &form).await
}
