//! Device-code flow (RFC 8628) for headless and remote sign-in.
//!
//! Shape a CLI drives:
//! 1. [`request`] returns a `user_code` and `verification_uri` to show the user.
//! 2. [`DeviceAuthorization::poll`] waits, honouring the server's interval and
//!    `slow_down`, until the user approves or the code expires.

use std::time::Duration;
use std::time::Instant;

use serde::Deserialize;

use crate::credentials::Credential;
use crate::error::Error;
use crate::error::Result;
use crate::flow::TokenErrorResponse;
use crate::flow::http_client;
use crate::flow::post_token_form;
use crate::provider::DeviceCodeConfig;

/// The device-authorization response (RFC 8628 §3.2).
#[derive(Deserialize)]
pub(crate) struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub interval: Option<i64>,
}

impl std::fmt::Debug for DeviceAuthorizationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `device_code` is a bearer credential for the token endpoint; a derived
        // Debug would put it into logs (CWE-532). `user_code` and the
        // verification URIs are front-channel values and stay visible.
        f.debug_struct("DeviceAuthorizationResponse")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// A pending device authorization the user must approve out of band.
pub struct DeviceAuthorization {
    provider: String,
    config: DeviceCodeConfig,
    device_code: String,
    /// The short code the user types at the verification URL.
    pub user_code: String,
    /// Where the user goes to enter the code.
    pub verification_uri: String,
    /// A pre-filled verification URL (code embedded), when the provider supplies it.
    pub verification_uri_complete: Option<String>,
    /// How long the codes remain valid.
    pub expires_in: Duration,
    interval: Duration,
}

/// Kick off a device-code sign-in.
#[tracing::instrument(level = "debug", skip_all, fields(provider = %provider))]
pub async fn request(provider: &str, config: &DeviceCodeConfig) -> Result<DeviceAuthorization> {
    tracing::debug!("requesting device authorization");
    let client = http_client()?;
    let scope = config.scopes.join(" ");
    let mut form: Vec<(&str, &str)> = vec![("client_id", config.client_id.as_str())];
    if !scope.is_empty() {
        form.push(("scope", scope.as_str()));
    }

    let response = client
        .post(&config.device_authorization_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        let detail =
            crate::flow::oauth_error_detail(&body).unwrap_or_else(|| format!("HTTP {status}"));
        return Err(Error::Authorization(format!(
            "device authorization failed: {detail}"
        )));
    }
    let parsed: DeviceAuthorizationResponse = serde_json::from_str(&body)
        .map_err(|e| Error::Malformed(format!("device authorization response: {e}")))?;
    if parsed.device_code.trim().is_empty()
        || parsed.user_code.trim().is_empty()
        || parsed.verification_uri.trim().is_empty()
    {
        return Err(Error::Malformed(
            "device authorization response contained empty required fields".to_string(),
        ));
    }
    Ok(DeviceAuthorization {
        provider: provider.to_string(),
        config: config.clone(),
        device_code: parsed.device_code,
        user_code: parsed.user_code,
        verification_uri: parsed.verification_uri,
        verification_uri_complete: parsed.verification_uri_complete,
        expires_in: Duration::from_secs(parsed.expires_in.unwrap_or(900).max(0) as u64),
        // RFC 8628 §3.5: default to 5s when the server omits the interval.
        interval: Duration::from_secs(parsed.interval.unwrap_or(5).max(1) as u64),
    })
}

impl DeviceAuthorization {
    /// Poll the token endpoint until the user approves, the code expires, or
    /// `max_wait` elapses. Honours `authorization_pending` and `slow_down` per
    /// RFC 8628 §3.5; every other error fails loud.
    #[tracing::instrument(level = "debug", skip_all, fields(provider = %self.provider))]
    pub async fn poll(self, max_wait: Duration) -> Result<Credential> {
        let client = http_client()?;
        let deadline = Instant::now() + max_wait.min(self.expires_in);
        let mut interval = self.interval;
        tracing::debug!("polling for device authorization approval");

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                tracing::warn!("device authorization timed out");
                return Err(Error::Timeout);
            }
            // Never sleep past the deadline: a server-provided `interval` larger than
            // the time left must not extend the wait beyond `max_wait` (a hostile or
            // buggy `interval` would otherwise hang the sign-in far past the timeout).
            tokio::time::sleep(interval.min(remaining)).await;

            let form = [
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", self.device_code.as_str()),
                ("client_id", self.config.client_id.as_str()),
            ];

            match post_token_form(&client, &self.provider, &self.config.token_url, &form).await {
                Ok(credential) => {
                    tracing::debug!("device authorization approved");
                    return Ok(credential);
                }
                Err(Error::Authorization(detail)) => match classify(&detail) {
                    DevicePollOutcome::Pending => continue,
                    DevicePollOutcome::SlowDown => {
                        interval += Duration::from_secs(5);
                        tracing::debug!(
                            interval_secs = interval.as_secs(),
                            "server asked to slow down"
                        );
                        continue;
                    }
                    DevicePollOutcome::Denied => {
                        tracing::warn!("user denied the device authorization");
                        return Err(Error::Cancelled);
                    }
                    DevicePollOutcome::Expired => {
                        tracing::warn!("device code expired before approval");
                        return Err(Error::Timeout);
                    }
                    DevicePollOutcome::Fatal => return Err(Error::Authorization(detail)),
                },
                Err(other) => return Err(other),
            }
        }
    }
}

/// The distinct meanings of an OAuth error during device-code polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DevicePollOutcome {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Fatal,
}

/// Map an OAuth `error` code (the leading token of the detail string) to its
/// device-poll meaning.
pub(crate) fn classify(detail: &str) -> DevicePollOutcome {
    let code = detail.split(':').next().unwrap_or(detail).trim();
    match code {
        "authorization_pending" => DevicePollOutcome::Pending,
        "slow_down" => DevicePollOutcome::SlowDown,
        "access_denied" => DevicePollOutcome::Denied,
        "expired_token" => DevicePollOutcome::Expired,
        _ => DevicePollOutcome::Fatal,
    }
}

/// Parse a raw device-token error body into an OAuth error code (exposed for the
/// shared token path's callers/tests).
#[allow(dead_code)]
pub(crate) fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<TokenErrorResponse>(body)
        .ok()
        .map(|e| e.error)
}
