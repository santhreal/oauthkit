//! Browser authorization-code flow with PKCE and a loopback redirect.
//!
//! The shape a CLI drives:
//! 1. [`begin`] binds a local listener and returns the `authorize_url`.
//! 2. The CLI opens that URL (browser) and shows it as a fallback.
//! 3. [`AuthorizationSession::wait`] blocks for the redirect, validates the
//!    `state`, and exchanges the code for a [`Credential`].

use std::io::Cursor;
use std::time::Duration;
use std::time::Instant;

use url::Url;

use crate::credentials::Credential;
use crate::error::Error;
use crate::error::Result;
use crate::flow::http_client;
use crate::flow::post_token_form;
use crate::pkce::PkceCodes;
use crate::pkce::generate_pkce;
use crate::pkce::generate_state;
use crate::provider::OAuthConfig;

/// The minimal HTML shown in the browser tab after a successful redirect.
const SUCCESS_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>Signed in</title></head><body style=\"background:#0b0b0d;color:#c7c9d1;\
font-family:ui-monospace,Menlo,monospace;display:flex;height:100vh;margin:0;\
align-items:center;justify-content:center\"><div style=\"text-align:center\">\
<div style=\"color:#c0c4cc;font-size:18px;letter-spacing:.08em\">SIGNED IN</div>\
<div style=\"margin-top:10px;color:#6b6f7a\">You can close this window and return \
to the terminal.</div></div></body></html>";

/// A begun authorization: the URL to open and the session to await.
pub struct BeganAuthorization {
    /// The full authorization URL to open in the user's browser.
    pub authorize_url: String,
    /// The pending session; call [`AuthorizationSession::wait`] to complete it.
    pub session: AuthorizationSession,
}

/// A bound loopback listener awaiting the OAuth redirect for one sign-in.
pub struct AuthorizationSession {
    provider: String,
    config: OAuthConfig,
    pkce: PkceCodes,
    state: String,
    redirect_uri: String,
    callback_path: String,
    server: tiny_http::Server,
}

/// Begin an authorization-code sign-in: bind the loopback listener and build the
/// authorize URL (with PKCE challenge and anti-CSRF state).
#[tracing::instrument(level = "debug", skip_all, fields(provider = %provider))]
pub fn begin(provider: &str, config: &OAuthConfig) -> Result<BeganAuthorization> {
    let pkce = generate_pkce();
    let state = generate_state();

    // Bind the loopback listener first so the redirect URI names a real port,
    // unless the provider mandates a fixed registered redirect.
    let (server, redirect_uri, callback_path) = match &config.redirect_uri {
        Some(fixed) => {
            // A fixed redirect still needs a listener on the port it names, and
            // the callback path must match the path the browser will hit.
            let mut url = Url::parse(fixed)
                .map_err(|e| Error::Malformed(format!("invalid redirect_uri `{fixed}`: {e}")))?;
            let port = url.port().ok_or_else(|| {
                Error::Loopback(format!("fixed redirect_uri `{fixed}` has no explicit port"))
            })?;
            let server = tiny_http::Server::http(("127.0.0.1", port))
                .map_err(|e| Error::Loopback(e.to_string()))?;
            let actual_port = server
                .server_addr()
                .to_ip()
                .map(|addr| addr.port())
                .ok_or_else(|| Error::Loopback("listener has no IP address".into()))?;
            if actual_port != port {
                url.set_port(Some(actual_port))
                    .map_err(|_| Error::Loopback(format!("could not set port on `{fixed}`")))?;
            }
            let path = url.path().to_string();
            let redirect_uri = url.to_string();
            (server, redirect_uri, path)
        }
        None => {
            let requested_port = config.loopback_port.unwrap_or(0);
            let server = tiny_http::Server::http(("127.0.0.1", requested_port))
                .map_err(|e| Error::Loopback(e.to_string()))?;
            let port = server
                .server_addr()
                .to_ip()
                .map(|addr| addr.port())
                .ok_or_else(|| Error::Loopback("listener has no IP address".into()))?;
            let redirect_uri = format!("http://127.0.0.1:{port}/callback");
            (server, redirect_uri, "/callback".to_string())
        }
    };

    let authorize_url = build_authorize_url(config, &pkce, &state, &redirect_uri)?;

    Ok(BeganAuthorization {
        authorize_url,
        session: AuthorizationSession {
            provider: provider.to_string(),
            config: config.clone(),
            pkce,
            state,
            redirect_uri,
            callback_path,
            server,
        },
    })
}

/// Assemble the front-channel authorize URL.
fn build_authorize_url(
    config: &OAuthConfig,
    pkce: &PkceCodes,
    state: &str,
    redirect_uri: &str,
) -> Result<String> {
    let mut url = Url::parse(&config.authorize_url)
        .map_err(|e| Error::Malformed(format!("invalid authorize_url: {e}")))?;
    {
        // Assemble the query as owned pairs first so the typed/protocol parameters
        // establish the set of reserved keys, then append only the custom
        // `extra_authorize_params` that do not collide (some providers reject a
        // repeated `scope`/`prompt`/`audience`).
        let scope = config.scopes.join(" ");
        let mut pairs: Vec<(&str, &str)> = vec![
            ("response_type", "code"),
            ("client_id", &config.client_id),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("code_challenge", &pkce.code_challenge),
            ("code_challenge_method", "S256"),
        ];
        if !config.scopes.is_empty() {
            pairs.push(("scope", &scope));
        }
        if let Some(audience) = &config.audience {
            pairs.push(("audience", audience));
        }
        if let Some(prompt) = &config.prompt {
            pairs.push(("prompt", prompt));
        }
        if let Some(login_hint) = &config.login_hint {
            pairs.push(("login_hint", login_hint));
        }
        let reserved: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        for (key, value) in &config.extra_authorize_params {
            if reserved.contains(&key.as_str()) {
                // A typed field or protocol parameter already owns this key; the
                // custom duplicate is dropped rather than emitted twice.
                continue;
            }
            pairs.push((key, value));
        }

        let mut q = url.query_pairs_mut();
        for (key, value) in pairs {
            q.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

impl AuthorizationSession {
    /// The exact redirect URI registered for this session (useful to display).
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Block until the browser redirect arrives (or `timeout` elapses), validate
    /// it, and exchange the authorization code for a [`Credential`].
    #[tracing::instrument(level = "debug", skip_all, fields(provider = %self.provider))]
    pub async fn wait(self, timeout: Duration) -> Result<Credential> {
        let AuthorizationSession {
            provider,
            config,
            pkce,
            state,
            redirect_uri,
            callback_path,
            server,
        } = self;

        tracing::debug!("waiting for the browser redirect on the loopback listener");
        // The loopback accept is synchronous; keep it off the async reactor.
        let code = tokio::task::spawn_blocking(move || {
            accept_code(&server, &state, &callback_path, timeout)
        })
        .await
        .map_err(|e| Error::Loopback(format!("loopback task failed: {e}")))??;

        tracing::debug!("received authorization code, exchanging for a token");
        let client = http_client()?;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", config.client_id.as_str()),
            ("code_verifier", pkce.code_verifier.as_str()),
        ];
        post_token_form(&client, &provider, &config.token_url, &form).await
    }
}

/// Accept exactly one loopback request carrying `?code=&state=`, validate the
/// state, answer the browser, and return the code. Fails loud on `?error=`,
/// state mismatch, or timeout: no silent fallback.
fn accept_code(
    server: &tiny_http::Server,
    expected_state: &str,
    expected_path: &str,
    timeout: Duration,
) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout);
        }
        let request = match server.recv_timeout(remaining) {
            Ok(Some(req)) => req,
            Ok(None) => return Err(Error::Timeout),
            Err(e) => return Err(Error::Loopback(e.to_string())),
        };

        // Only the callback path carries the grant; ignore favicon/etc probes.
        let full = format!("http://127.0.0.1{}", request.url());
        let parsed = match Url::parse(&full) {
            Ok(u) => u,
            Err(_) => {
                respond(request, 400, "bad request");
                continue;
            }
        };
        if parsed.path() != expected_path {
            respond(request, 404, "not found");
            continue;
        }

        let mut code = None;
        let mut state = None;
        let mut oauth_error = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => oauth_error = Some(value.into_owned()),
                _ => {}
            }
        }

        if let Some(err) = oauth_error {
            respond(request, 200, "sign-in failed; you can close this window");
            return Err(Error::Authorization(err));
        }
        match (code, state) {
            (Some(code), Some(state)) if state == expected_state => {
                respond_html(request, SUCCESS_HTML);
                return Ok(code);
            }
            (_, Some(_)) => {
                respond(request, 400, "state mismatch");
                return Err(Error::StateMismatch);
            }
            _ => {
                // A stray request with neither code nor error: keep waiting.
                respond(request, 400, "missing authorization code");
            }
        }
    }
}

fn respond(request: tiny_http::Request, status: u16, message: &str) {
    let response = tiny_http::Response::from_string(message).with_status_code(status);
    let _ = request.respond(response);
}

fn respond_html(request: tiny_http::Request, html: &str) {
    let data = html.as_bytes().to_vec();
    let len = data.len();
    let header =
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
            .expect("static content-type header is valid");
    let response = tiny_http::Response::new(
        tiny_http::StatusCode(200),
        vec![header],
        Cursor::new(data),
        Some(len),
        None,
    );
    let _ = request.respond(response);
}
