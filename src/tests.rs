//! Unit tests for the SDK: registry data, validation, flows-that-need-no-network,
//! credential handling, and store behaviour. Network-driven token exchange and
//! device polling are covered by their own error-classification units.

use crate::AuthMethod;
use crate::Credential;
use crate::CredentialKind;
use crate::CredentialStore;
use crate::MemoryStore;
use crate::Registry;
use crate::flow::authorization_code;
use crate::provider::ApiKeyConfig;
use crate::provider::DeviceCodeConfig;
use crate::provider::OAuthConfig;
use crate::provider::Provider;

fn oauth_config() -> OAuthConfig {
    OAuthConfig {
        authorize_url: "https://auth.example.com/authorize".to_string(),
        token_url: "https://auth.example.com/token".to_string(),
        client_id: "client-123".to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        redirect_uri: None,
        loopback_port: None,
        audience: None,
        prompt: None,
        login_hint: None,
        extra_authorize_params: vec![("prompt".to_string(), "login".to_string())],
        label: None,
    }
}

/// A wiremock responder that replies with a fixed sequence of `(status, body)`
/// pairs indexed by call count, repeating the final entry once exhausted. It lets
/// a single mounted mock drive a multi-step device poll (e.g. `authorization_pending`
/// then `slow_down` then success) deterministically, independent of wiremock's
/// mock-selection order.
struct SeqResponder {
    calls: std::sync::atomic::AtomicUsize,
    steps: Vec<(u16, serde_json::Value)>,
}

impl SeqResponder {
    fn new(steps: Vec<(u16, serde_json::Value)>) -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            steps,
        }
    }
}

impl wiremock::Respond for SeqResponder {
    fn respond(&self, _: &wiremock::Request) -> wiremock::ResponseTemplate {
        let i = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (status, body) = &self.steps[i.min(self.steps.len() - 1)];
        wiremock::ResponseTemplate::new(*status).set_body_json(body.clone())
    }
}

#[test]
fn builtin_registry_loads_and_lists_expected_providers() {
    let registry = Registry::builtin().expect("built-in registry parses");
    let ids: Vec<&str> = registry.providers().iter().map(|p| p.id.as_str()).collect();

    // The registry must actually carry the shipped breadth, in order.
    assert!(
        ids.len() >= 13,
        "expected >=13 providers, got {}",
        ids.len()
    );
    for expected in [
        "anthropic",
        "openai",
        "github-copilot",
        "google",
        "deepseek",
        "moonshot",
        "zai",
        "openrouter",
        "xai",
        "groq",
        "mistral",
        "azure-openai",
        "amazon-bedrock",
    ] {
        assert!(
            registry.get(expected).is_some(),
            "built-in registry is missing `{expected}`"
        );
    }

    // Spot-check concrete data rather than mere presence.
    let anthropic = registry.get("anthropic").unwrap();
    assert_eq!(anthropic.display_name, "Anthropic");
    let key = anthropic.api_key().expect("anthropic offers api key");
    assert_eq!(key.env_var.as_deref(), Some("ANTHROPIC_API_KEY"));
    assert_eq!(key.key_prefix.as_deref(), Some("sk-ant-"));

    // GitHub Copilot is the device-code provider.
    let copilot = registry.get("github-copilot").unwrap();
    let device = copilot.device().expect("copilot offers device flow");
    assert_eq!(
        device.device_authorization_url,
        "https://github.com/login/device/code"
    );
    assert_eq!(device.client_id, "Iv1.b507a08c87ecfe98");
}

#[test]
fn registry_rejects_duplicate_ids() {
    let toml = r#"
[[provider]]
id = "dup"
display_name = "One"
[[provider.methods]]
flow = "api_key"

[[provider]]
id = "dup"
display_name = "Two"
[[provider.methods]]
flow = "api_key"
"#;
    let err = Registry::from_toml(toml).unwrap_err();
    assert!(
        err.to_string().contains("duplicate provider id `dup`"),
        "unexpected error: {err}"
    );
}

#[test]
fn registry_rejects_provider_without_methods() {
    let toml = r#"
[[provider]]
id = "empty"
display_name = "Empty"
methods = []
"#;
    let err = Registry::from_toml(toml).unwrap_err();
    assert!(
        err.to_string().contains("defines no auth methods"),
        "unexpected error: {err}"
    );
}

#[test]
fn registry_rejects_oauth_missing_client_id() {
    let toml = r#"
[[provider]]
id = "broken"
display_name = "Broken"
[[provider.methods]]
flow = "oauth"
authorize_url = "https://x/authorize"
token_url = "https://x/token"
client_id = ""
"#;
    let err = Registry::from_toml(toml).unwrap_err();
    assert!(
        err.to_string()
            .contains("missing authorize_url/token_url/client_id"),
        "unexpected error: {err}"
    );
}

#[test]
fn merge_overrides_by_id_and_appends_new() {
    let mut base = Registry::builtin().unwrap();
    let before = base.providers().len();

    let extra = Registry::from_toml(
        r#"
[[provider]]
id = "openai"
display_name = "OpenAI (custom)"
[[provider.methods]]
flow = "api_key"
env_var = "MY_OPENAI_KEY"

[[provider]]
id = "acme"
display_name = "Acme"
[[provider.methods]]
flow = "api_key"
env_var = "ACME_KEY"
"#,
    )
    .unwrap();
    base.merge(extra);

    // openai overridden in place, acme appended: exactly one net new provider.
    assert_eq!(base.providers().len(), before + 1);
    assert_eq!(base.get("openai").unwrap().display_name, "OpenAI (custom)");
    assert_eq!(
        base.get("openai")
            .unwrap()
            .api_key()
            .unwrap()
            .env_var
            .as_deref(),
        Some("MY_OPENAI_KEY")
    );
    assert!(base.get("acme").is_some());
}

#[test]
fn api_key_accept_enforces_prefix_and_nonempty() {
    let config = ApiKeyConfig {
        env_var: Some("X_KEY".to_string()),
        console_url: None,
        key_prefix: Some("sk-".to_string()),
        label: None,
    };

    let ok = crate::flow::api_key::accept("x", &config, "  sk-abc123  ").unwrap();
    assert_eq!(ok.kind(), CredentialKind::ApiKey);
    assert_eq!(ok.api_key_value().map(|s| s.as_str()), Some("sk-abc123"));

    let empty = crate::flow::api_key::accept("x", &config, "   ").unwrap_err();
    assert!(empty.to_string().contains("empty"), "got {empty}");

    let wrong = crate::flow::api_key::accept("x", &config, "nope-123").unwrap_err();
    assert!(
        wrong.to_string().contains("expected `sk-` prefix"),
        "got {wrong}"
    );
}

#[test]
fn api_key_from_env_reads_declared_var() {
    let var = "OAUTHKIT_TEST_KEY_ENV";
    let config = ApiKeyConfig {
        env_var: Some(var.to_string()),
        console_url: None,
        key_prefix: None,
        label: None,
    };
    // SAFETY-ish: single-threaded test process for this var.
    unsafe { std::env::set_var(var, "from-env-value") };
    assert_eq!(
        crate::flow::api_key::from_env(&config).as_deref(),
        Some("from-env-value")
    );
    // A key exported via `KEY=$(cat file)` carries surrounding whitespace/newlines; `from_env` must
    // trim it (matching `accept`) so it does not fail auth for whitespace the interactive path strips.
    unsafe { std::env::set_var(var, "  sk-trimmed-value\n") };
    assert_eq!(
        crate::flow::api_key::from_env(&config).as_deref(),
        Some("sk-trimmed-value")
    );
    unsafe { std::env::set_var(var, "   ") };
    assert_eq!(crate::flow::api_key::from_env(&config), None);
    unsafe { std::env::remove_var(var) };
    assert_eq!(crate::flow::api_key::from_env(&config), None);
}

#[test]
fn begin_oauth_builds_a_complete_pkce_authorize_url_on_a_loopback() {
    let config = oauth_config();
    let begun = authorization_code::begin("example", &config).expect("begin binds a listener");

    let url = url::Url::parse(&begun.authorize_url).expect("authorize url is valid");
    assert_eq!(url.host_str(), Some("auth.example.com"));
    assert_eq!(url.path(), "/authorize");

    let params: std::collections::BTreeMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("client_id").map(String::as_str),
        Some("client-123")
    );
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert_eq!(
        params.get("scope").map(String::as_str),
        Some("openid profile")
    );
    assert_eq!(params.get("prompt").map(String::as_str), Some("login"));
    assert!(params.get("code_challenge").is_some_and(|c| !c.is_empty()));
    assert!(params.get("state").is_some_and(|s| !s.is_empty()));

    // The redirect the SDK registered is a real loopback callback.
    let redirect = params.get("redirect_uri").expect("redirect_uri present");
    assert!(
        redirect.starts_with("http://127.0.0.1:") && redirect.ends_with("/callback"),
        "unexpected redirect {redirect}"
    );
    assert_eq!(begun.session.redirect_uri(), redirect);
}

#[test]
fn typed_authorize_params_are_merged_and_win_over_colliding_extras() {
    let mut config = oauth_config();
    config.audience = Some("https://api.example.com".to_string());
    config.prompt = Some("consent".to_string());
    config.login_hint = Some("user@example.com".to_string());
    // A custom extra that collides with the typed `prompt` must be dropped (the
    // typed value wins and the URL carries exactly one `prompt`); a non-colliding
    // custom extra must survive.
    config.extra_authorize_params = vec![
        ("prompt".to_string(), "login".to_string()),
        ("connection".to_string(), "google-oauth2".to_string()),
    ];

    let begun = authorization_code::begin("example", &config).expect("begin binds a listener");
    let url = url::Url::parse(&begun.authorize_url).expect("authorize url is valid");

    let prompts: Vec<String> = url
        .query_pairs()
        .filter(|(k, _)| k == "prompt")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(
        prompts,
        vec!["consent".to_string()],
        "typed prompt must win and appear exactly once"
    );

    let params: std::collections::BTreeMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        params.get("audience").map(String::as_str),
        Some("https://api.example.com")
    );
    assert_eq!(
        params.get("login_hint").map(String::as_str),
        Some("user@example.com")
    );
    assert_eq!(
        params.get("connection").map(String::as_str),
        Some("google-oauth2"),
        "non-colliding custom extra must survive"
    );
}

#[test]
fn oauth_state_differs_across_sessions() {
    let config = oauth_config();
    let a = authorization_code::begin("example", &config).unwrap();
    let b = authorization_code::begin("example", &config).unwrap();
    let state_of = |u: &str| {
        url::Url::parse(u)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap()
    };
    assert_ne!(
        state_of(&a.authorize_url),
        state_of(&b.authorize_url),
        "each session must mint a fresh anti-CSRF state"
    );
}

#[test]
fn fixed_redirect_uri_with_port_zero_gets_an_ephemeral_port() {
    let mut config = oauth_config();
    config.redirect_uri = Some("http://127.0.0.1:0/custom/callback".to_string());

    let begun = authorization_code::begin("example", &config)
        .expect("begin binds a listener on the requested port");
    let url = url::Url::parse(&begun.authorize_url).unwrap();
    let params: std::collections::BTreeMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let redirect = params.get("redirect_uri").expect("redirect_uri present");
    let redirect_url = url::Url::parse(redirect).expect("redirect_uri is a valid URL");
    assert_eq!(redirect_url.host_str(), Some("127.0.0.1"));
    assert_eq!(redirect_url.path(), "/custom/callback");
    assert!(
        redirect_url.port().is_some_and(|p| p != 0),
        "port 0 must be replaced with the actual bound port, got {redirect}"
    );
    assert_eq!(begun.session.redirect_uri(), redirect);
}

#[test]
fn fixed_redirect_uri_with_explicit_port_and_root_path_is_preserved() {
    let mut config = oauth_config();
    config.redirect_uri = Some("http://127.0.0.1:8080/".to_string());

    let begun = authorization_code::begin("example", &config)
        .expect("begin binds a listener on the fixed port");
    let url = url::Url::parse(&begun.authorize_url).unwrap();
    let params: std::collections::BTreeMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let redirect = params.get("redirect_uri").expect("redirect_uri present");
    assert_eq!(redirect, "http://127.0.0.1:8080/");
    assert_eq!(begun.session.redirect_uri(), redirect);
}

#[tokio::test]
async fn authorization_code_custom_redirect_path_reaches_the_callback_and_exchanges() {
    use std::time::Duration;

    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let token_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-token",
            "token_type": "Bearer",
        })))
        .mount(&token_server)
        .await;

    let mut config = oauth_config();
    config.token_url = format!("{}/token", token_server.uri());
    config.redirect_uri = Some("http://127.0.0.1:0/custom/callback".to_string());

    let begun = authorization_code::begin("example", &config)
        .expect("begin binds a listener with an ephemeral port");

    let state = url::Url::parse(&begun.authorize_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let redirect_uri = begun.session.redirect_uri().to_string();

    let session_task =
        tokio::spawn(async move { begun.session.wait(Duration::from_secs(5)).await });

    let client = reqwest::Client::new();
    let request_url = format!("{redirect_uri}?code=the-code&state={state}");
    let response = client
        .get(request_url)
        .send()
        .await
        .expect("client can reach the local loopback server");
    assert!(response.status().is_success());

    let credential = session_task
        .await
        .expect("wait task completed")
        .expect("redirect was accepted and token was exchanged");
    assert_eq!(credential.provider(), "example");
    assert_eq!(credential.secret(), Some("access-token"));
    assert_eq!(credential.token_type().map(|s| s.as_str()), Some("Bearer"));
}

#[tokio::test]
async fn authorization_code_rejects_a_state_mismatch() {
    use std::time::Duration;

    use crate::Error;

    let config = oauth_config();
    let begun =
        authorization_code::begin("example", &config).expect("begin binds a loopback listener");
    let redirect_uri = begun.session.redirect_uri().to_string();

    let session_task =
        tokio::spawn(async move { begun.session.wait(Duration::from_secs(5)).await });

    // Deliver a callback whose `state` does not match the session's anti-CSRF value.
    let client = reqwest::Client::new();
    let request_url = format!("{redirect_uri}?code=the-code&state=forged-state");
    let response = client
        .get(request_url)
        .send()
        .await
        .expect("client can reach the loopback server");
    assert_eq!(
        response.status().as_u16(),
        400,
        "browser is told the state mismatched"
    );

    let err = session_task
        .await
        .expect("wait task completed")
        .expect_err("a forged state must fail loud, never yield a credential");
    assert!(
        matches!(err, Error::StateMismatch),
        "expected StateMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn authorization_code_fails_loud_on_an_error_redirect() {
    use std::time::Duration;

    use crate::Error;

    let config = oauth_config();
    let begun =
        authorization_code::begin("example", &config).expect("begin binds a loopback listener");
    let redirect_uri = begun.session.redirect_uri().to_string();

    let session_task =
        tokio::spawn(async move { begun.session.wait(Duration::from_secs(5)).await });

    // The provider redirected with `?error=` instead of a code (user denied consent).
    let client = reqwest::Client::new();
    let request_url = format!("{redirect_uri}?error=access_denied");
    let response = client
        .get(request_url)
        .send()
        .await
        .expect("client can reach the loopback server");
    assert!(
        response.status().is_success(),
        "browser still gets a friendly page"
    );

    let err = session_task
        .await
        .expect("wait task completed")
        .expect_err("an error redirect must surface, never a degraded success");
    match err {
        Error::Authorization(detail) => assert!(
            detail.contains("access_denied"),
            "the OAuth error code is surfaced: {detail}"
        ),
        other => panic!("expected Error::Authorization, got {other:?}"),
    }
}

#[tokio::test]
async fn device_poll_honors_pending_and_slow_down_before_succeeding() {
    use std::time::Duration;

    use crate::flow::device_code;
    use crate::provider::DeviceCodeConfig;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let device_server = MockServer::start().await;
    let token_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "device-abc",
            "user_code": "WXYZ-9876",
            "verification_uri": "https://auth.example.com/verify",
            "expires_in": 900,
            "interval": 1,
        })))
        .mount(&device_server)
        .await;

    // First poll -> authorization_pending, second -> slow_down, third -> success.
    // RFC 8628 §3.5 returns these as 400 error bodies; success is a 200 grant.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(SeqResponder::new(vec![
            (400, serde_json::json!({ "error": "authorization_pending" })),
            (400, serde_json::json!({ "error": "slow_down" })),
            (
                200,
                serde_json::json!({ "access_token": "device-access-token", "token_type": "Bearer" }),
            ),
        ]))
        .mount(&token_server)
        .await;

    let config = DeviceCodeConfig {
        device_authorization_url: format!("{}/device", device_server.uri()),
        token_url: format!("{}/token", token_server.uri()),
        client_id: "client-123".to_string(),
        scopes: vec!["openid".to_string()],
        label: None,
    };

    let auth = device_code::request("acme", &config)
        .await
        .expect("device authorization request succeeds");
    // A generous deadline: paused time auto-advances the interval/slow_down sleeps.
    let credential = auth
        .poll(Duration::from_secs(600))
        .await
        .expect("poll must keep going through pending/slow_down and then succeed");

    assert_eq!(credential.provider(), "acme");
    assert_eq!(credential.secret(), Some("device-access-token"));
    assert_eq!(credential.token_type().map(|s| s.as_str()), Some("Bearer"));
}

#[tokio::test]
async fn device_poll_returns_cancelled_on_access_denied() {
    use std::time::Duration;

    use crate::Error;
    use crate::flow::device_code;
    use crate::provider::DeviceCodeConfig;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let device_server = MockServer::start().await;
    let token_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "device-abc",
            "user_code": "WXYZ-9876",
            "verification_uri": "https://auth.example.com/verify",
            "expires_in": 900,
            "interval": 1,
        })))
        .mount(&device_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "access_denied",
            "error_description": "user rejected the request",
        })))
        .mount(&token_server)
        .await;

    let config = DeviceCodeConfig {
        device_authorization_url: format!("{}/device", device_server.uri()),
        token_url: format!("{}/token", token_server.uri()),
        client_id: "client-123".to_string(),
        scopes: vec!["openid".to_string()],
        label: None,
    };

    let auth = device_code::request("acme", &config)
        .await
        .expect("device authorization request succeeds");
    let err = auth
        .poll(Duration::from_secs(600))
        .await
        .expect_err("access_denied must terminate polling with a cancellation");
    assert!(
        matches!(err, Error::Cancelled),
        "expected Error::Cancelled, got {err:?}"
    );
}

#[test]
fn credential_expiry_and_secret_selection() {
    let oauth = Credential::oauth(
        "p",
        "access-tok".into(),
        Some("refresh".into()),
        Some(1_000),
        None,
    );
    assert!(oauth.is_expired(1_000));
    assert!(oauth.is_expired(2_000));
    assert!(!oauth.is_expired(999));
    assert_eq!(oauth.secret(), Some("access-tok"));

    let key = Credential::api_key("p", "sk-xyz".into());
    assert!(!key.is_expired(i64::MAX)); // API keys never expire on their own.
    assert_eq!(key.secret(), Some("sk-xyz"));
}

#[test]
fn credential_debug_never_leaks_the_secret() {
    let oauth = Credential::oauth("p", "super-secret-token".into(), None, None, None);
    let rendered = format!("{oauth:?}");
    assert!(
        !rendered.contains("super-secret-token"),
        "debug leaked token: {rendered}"
    );
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn memory_store_roundtrips_and_deletes() {
    let store = MemoryStore::new();
    assert_eq!(store.providers().unwrap(), Vec::<String>::new());

    let cred = Credential::api_key("openai", "sk-abc".into());
    store.put(&cred).unwrap();
    assert_eq!(store.get("openai").unwrap().as_ref(), Some(&cred));
    assert_eq!(store.providers().unwrap(), vec!["openai".to_string()]);

    store.delete("openai").unwrap();
    assert_eq!(store.get("openai").unwrap(), None);
    assert_eq!(store.providers().unwrap(), Vec::<String>::new());
}

#[test]
fn provider_method_accessors_pick_the_right_method() {
    let provider = Provider {
        id: "multi".to_string(),
        display_name: "Multi".to_string(),
        note: None,
        methods: vec![
            AuthMethod::ApiKey(ApiKeyConfig {
                env_var: Some("K".to_string()),
                console_url: None,
                key_prefix: None,
                label: None,
            }),
            AuthMethod::Device(DeviceCodeConfig {
                device_authorization_url: "https://d".to_string(),
                token_url: "https://t".to_string(),
                client_id: "c".to_string(),
                scopes: vec![],
                label: None,
            }),
        ],
    };
    assert!(provider.api_key().is_some());
    assert!(provider.device().is_some());
    assert!(provider.oauth().is_none());
    assert_eq!(provider.methods[0].kind(), "api_key");
    assert_eq!(provider.methods[1].kind(), "device");
}

#[test]
fn registry_rejects_provider_with_duplicate_method_kind() {
    let toml = r#"
[[provider]]
id = "dupe"
display_name = "Dupe"

[[provider.methods]]
flow = "api_key"
env_var = "A"

[[provider.methods]]
flow = "api_key"
env_var = "B"
"#;

    let err = Registry::from_toml(toml).unwrap_err();
    assert!(err.to_string().contains("more than one"), "got {err}");
    assert!(err.to_string().contains("api_key"), "got {err}");
}

#[test]
fn registry_rejects_oauth_malformed_urls() {
    let err = Registry::from_toml(
        r#"
[[provider]]
id = "bad"
display_name = "Bad"

[[provider.methods]]
flow = "oauth"
authorize_url = "not-a-url"
token_url = "https://auth.example.com/token"
client_id = "client"
"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("not a valid URL"), "got {err}");

    let err = Registry::from_toml(
        r#"
[[provider]]
id = "bad"
display_name = "Bad"

[[provider.methods]]
flow = "oauth"
authorize_url = "https://auth.example.com/authorize"
token_url = "ftp://auth.example.com/token"
client_id = "client"
"#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("must use http or https"),
        "got {err}"
    );
}

#[test]
fn registry_rejects_oauth_redirect_uri_loopback_conflict() {
    let err = Registry::from_toml(
        r#"
[[provider]]
id = "bad"
display_name = "Bad"

[[provider.methods]]
flow = "oauth"
authorize_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "client"
redirect_uri = "http://127.0.0.1:8080/callback"
loopback_port = 8080
"#,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("both redirect_uri and loopback_port"),
        "got {err}"
    );

    let err = Registry::from_toml(
        r#"
[[provider]]
id = "bad"
display_name = "Bad"

[[provider.methods]]
flow = "oauth"
authorize_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "client"
redirect_uri = "http://example.com:8080/callback"
"#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("127.0.0.1 or localhost"),
        "got {err}"
    );

    let err = Registry::from_toml(
        r#"
[[provider]]
id = "bad"
display_name = "Bad"

[[provider.methods]]
flow = "oauth"
authorize_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "client"
redirect_uri = "http://127.0.0.1/callback"
"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("explicit port"), "got {err}");
}

#[test]
fn device_poll_classifies_every_rfc8628_error() {
    use crate::flow::device_code::DevicePollOutcome;
    use crate::flow::device_code::classify;

    // The four defined polling errors map to their retry/terminal meaning.
    assert_eq!(
        classify("authorization_pending"),
        DevicePollOutcome::Pending
    );
    assert_eq!(classify("slow_down"), DevicePollOutcome::SlowDown);
    assert_eq!(classify("access_denied"), DevicePollOutcome::Denied);
    assert_eq!(classify("expired_token"), DevicePollOutcome::Expired);
    // A description suffix is tolerated: only the leading code is matched.
    assert_eq!(
        classify("authorization_pending: keep waiting"),
        DevicePollOutcome::Pending
    );
    // Anything else is fatal (fail loud, never a silent retry loop).
    assert_eq!(classify("invalid_grant"), DevicePollOutcome::Fatal);
    assert_eq!(classify("totally_unknown"), DevicePollOutcome::Fatal);
}

#[test]
fn device_error_code_extracts_the_oauth_error() {
    use crate::flow::device_code::error_code;

    assert_eq!(
        error_code(r#"{"error":"authorization_pending"}"#).as_deref(),
        Some("authorization_pending")
    );
    assert_eq!(
        error_code(r#"{"error":"slow_down","error_description":"too fast"}"#).as_deref(),
        Some("slow_down")
    );
    // A body with no OAuth error shape yields None rather than a bogus code.
    assert_eq!(error_code(r#"{"unrelated":true}"#), None);
    assert_eq!(error_code("not json at all"), None);
}

#[test]
fn token_error_response_parses_error_and_optional_description() {
    use crate::flow::TokenErrorResponse;

    let full: TokenErrorResponse =
        serde_json::from_str(r#"{"error":"invalid_grant","error_description":"expired"}"#).unwrap();
    assert_eq!(full.error, "invalid_grant");
    assert_eq!(full.error_description.as_deref(), Some("expired"));

    // error_description is optional (RFC 6749 §5.2).
    let bare: TokenErrorResponse = serde_json::from_str(r#"{"error":"invalid_request"}"#).unwrap();
    assert_eq!(bare.error, "invalid_request");
    assert_eq!(bare.error_description, None);
}

#[test]
fn expiry_from_expires_in_is_absolute_and_optional() {
    use crate::flow::expiry_from_expires_in;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    // No lifetime means no absolute expiry.
    assert_eq!(expiry_from_expires_in(None), None);

    // A finite lifetime becomes an absolute Unix time near now + lifetime.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expiry = expiry_from_expires_in(Some(3600)).expect("finite lifetime yields an expiry");
    assert!(
        (expiry - (now + 3600)).abs() <= 2,
        "expiry {expiry} should be ~{} (now+3600)",
        now + 3600
    );
}

// The shared token path (`post_token_form`) is exercised end-to-end through the
// public `refresh` entry point against a mock token endpoint.

#[tokio::test]
async fn refresh_parses_a_successful_grant_from_the_token_endpoint() {
    use crate::flow::refresh;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        })))
        .mount(&server)
        .await;

    let token_url = format!("{}/token", server.uri());
    let credential = refresh("acme", &token_url, "client-123", "old-refresh")
        .await
        .expect("a 200 grant must parse into a credential");

    assert_eq!(credential.provider(), "acme");
    assert_eq!(credential.secret(), Some("new-access-token"));
    assert_eq!(
        credential.refresh_token().map(|s| s.as_str()),
        Some("new-refresh-token")
    );
    assert_eq!(credential.token_type().map(|s| s.as_str()), Some("Bearer"));
    assert!(
        credential.expires_at_unix().is_some(),
        "expires_in becomes an absolute expiry"
    );
    // The token must never surface in Debug (CWE-532).
    assert!(!format!("{credential:?}").contains("new-access-token"));
}

#[tokio::test]
async fn refresh_fails_loud_on_an_oauth_error_response() {
    use crate::Error;
    use crate::flow::refresh;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "refresh token expired",
        })))
        .mount(&server)
        .await;

    let token_url = format!("{}/token", server.uri());
    let err = refresh("acme", &token_url, "client-123", "stale-refresh")
        .await
        .expect_err("an OAuth error response must fail, never a degraded success");

    match err {
        Error::Authorization(detail) => {
            assert!(
                detail.contains("invalid_grant"),
                "detail carries the code: {detail}"
            );
            assert!(
                detail.contains("refresh token expired"),
                "detail carries the description"
            );
        }
        other => panic!("expected Error::Authorization, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_rejects_a_malformed_success_body() {
    use crate::Error;
    use crate::flow::refresh;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;

    let token_url = format!("{}/token", server.uri());
    let err = refresh("acme", &token_url, "client-123", "refresh")
        .await
        .expect_err("a 200 that is not a valid grant must be rejected, not guessed");
    assert!(matches!(err, Error::Malformed(_)), "got {err:?}");
}

#[tokio::test]
async fn refresh_rejects_success_body_without_token_type() {
    use crate::Error;
    use crate::flow::refresh;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-token",
            // token_type intentionally omitted — RFC 6749 §5.1 says it is required.
        })))
        .mount(&server)
        .await;

    let token_url = format!("{}/token", server.uri());
    let err = refresh("acme", &token_url, "client-123", "refresh")
        .await
        .expect_err("a conforming token response requires token_type");

    assert!(matches!(err, Error::Malformed(_)), "got {err:?}");
}

// The capture buffer for the global tracing subscriber the secret-leak test
// installs. A *global* subscriber (installed exactly once, which rebuilds the
// callsite-interest cache) is required for reliability: with only a thread-local
// subscriber, a concurrent test that runs the same instrumented code with no
// subscriber caches those callsites as "disabled" globally, so the events never
// reach the buffer. The global subscriber keeps the callsites interested for the
// whole test binary.
fn global_tracing_capture() -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    static CAPTURE: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    CAPTURE
        .get_or_init(|| {
            let buf = Arc::new(Mutex::new(Vec::<u8>::new()));

            #[derive(Clone)]
            struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
            impl Write for CaptureWriter {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(bytes);
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
                type Writer = CaptureWriter;
                fn make_writer(&'a self) -> Self::Writer {
                    self.clone()
                }
            }

            let subscriber = tracing_subscriber::fmt()
                .with_writer(CaptureWriter(Arc::clone(&buf)))
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .finish();
            // Ignore an error if something else already set the global default; the
            // buffer simply stays empty in that case and the liveness assert catches it.
            let _ = tracing::subscriber::set_global_default(subscriber);
            buf
        })
        .clone()
}

#[test]
fn tracing_never_emits_token_material() {
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use crate::flow::refresh;

    // Distinctive sentinels so any leak into the log is unambiguous.
    const REQUEST_SECRET: &str = "SECRET-REFRESH-TOKEN-do-not-log";
    const ACCESS_SECRET: &str = "SECRET-ACCESS-TOKEN-do-not-log";
    const RESPONSE_REFRESH_SECRET: &str = "SECRET-NEW-REFRESH-do-not-log";
    // A provider id unique to this test, so its lines can be isolated from the
    // events other tests emit into the shared global buffer.
    const PROBE_PROVIDER: &str = "leakprobe-7f3a2b9c";

    let buf = global_tracing_capture();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds");

    let credential = runtime.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": ACCESS_SECRET,
                "refresh_token": RESPONSE_REFRESH_SECRET,
                "expires_in": 3600,
                "token_type": "Bearer",
            })))
            .mount(&server)
            .await;

        let token_url = format!("{}/token", server.uri());
        refresh(PROBE_PROVIDER, &token_url, "client-123", REQUEST_SECRET)
            .await
            .expect("refresh succeeds against the mock")
    });
    // Sanity: the flow really ran and produced the (secret) token.
    assert_eq!(credential.secret(), Some(ACCESS_SECRET));

    // Isolate only the lines from THIS test's flow (its unique provider id appears
    // in the span context of every event the flow emits).
    let logged = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    let mine: String = logged
        .lines()
        .filter(|line| line.contains(PROBE_PROVIDER))
        .collect::<Vec<_>>()
        .join("\n");

    // The instrumentation must have actually fired (otherwise the test proves
    // nothing). The token-path success event is emitted from `post_token_form`.
    assert!(
        mine.contains("token exchange succeeded"),
        "expected the token-path flow event in the log, got:\n{mine}"
    );
    // No token material of any kind may appear in the captured output (CWE-532).
    for secret in [REQUEST_SECRET, ACCESS_SECRET, RESPONSE_REFRESH_SECRET] {
        assert!(
            !mine.contains(secret),
            "token material `{secret}` leaked into tracing output:\n{mine}"
        );
    }
}

#[test]
fn oauth_error_detail_parses_rfc_error_and_description() {
    use crate::flow::oauth_error_detail;

    let detail = oauth_error_detail(r#"{"error":"invalid_client","error_description":"bad id"}"#)
        .expect("valid OAuth error body parses");
    assert!(
        detail.contains("invalid_client"),
        "detail has code: {detail}"
    );
    assert!(
        detail.contains("bad id"),
        "detail has description: {detail}"
    );

    let code_only =
        oauth_error_detail(r#"{"error":"access_denied"}"#).expect("code-only body parses");
    assert_eq!(code_only, "access_denied");

    assert!(
        oauth_error_detail("not json").is_none(),
        "non-JSON body yields no detail"
    );
}

#[tokio::test]
async fn token_request_times_out_on_a_slow_endpoint() {
    use std::time::Duration;
    use std::time::Instant;

    use crate::Error;
    use crate::flow::post_token_form;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "access_token": "x",
                    "token_type": "Bearer",
                }))
                .set_delay(Duration::from_secs(1)),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .connect_timeout(Duration::from_millis(10))
        .build()
        .expect("short-timeout client builds");

    let token_url = format!("{}/token", server.uri());
    let start = Instant::now();
    let err = post_token_form(&client, "acme", &token_url, &[])
        .await
        .expect_err("slow endpoint must time out");
    let elapsed = start.elapsed();

    assert!(matches!(err, Error::Http(_)), "got {err:?}");
    assert!(
        elapsed < Duration::from_millis(500),
        "timeout must abort early, got {elapsed:?}"
    );
}

#[tokio::test]
async fn device_authorization_request_surfaces_oauth_error_body() {
    use crate::Error;
    use crate::flow::device_code;
    use crate::provider::DeviceCodeConfig;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_client",
            "error_description": "unknown client id",
        })))
        .mount(&server)
        .await;

    let config = DeviceCodeConfig {
        device_authorization_url: format!("{}/device", server.uri()),
        token_url: "https://auth.example.com/token".to_string(),
        client_id: "bad-client".to_string(),
        scopes: vec!["openid".to_string()],
        label: None,
    };

    let result = device_code::request("acme", &config).await;
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("a 400 device-authorization response must fail"),
    };

    match err {
        Error::Authorization(detail) => {
            assert!(
                detail.contains("invalid_client"),
                "detail has code: {detail}"
            );
            assert!(
                detail.contains("unknown client id"),
                "detail has description: {detail}"
            );
        }
        other => panic!("expected Error::Authorization, got {other:?}"),
    }
}

#[tokio::test]
async fn auth_client_device_flow_completes_from_request_to_poll() {
    use std::time::Duration;

    use crate::AuthClient;
    use crate::MemoryStore;
    use crate::Registry;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    let device_server = MockServer::start().await;
    let token_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "device-123",
            "user_code": "ABCD-1234",
            "verification_uri": "https://auth.example.com/verify",
            "expires_in": 900,
            "interval": 0,
        })))
        .mount(&device_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "device-access-token",
            "token_type": "Bearer",
        })))
        .mount(&token_server)
        .await;

    let registry_toml = format!(
        r#"
[[provider]]
id = "test"
display_name = "Test"

[[provider.methods]]
flow = "device"
device_authorization_url = "{}/device"
token_url = "{}/token"
client_id = "client-123"
scopes = ["openid"]
"#,
        device_server.uri(),
        token_server.uri()
    );

    let registry = Registry::from_toml(&registry_toml).expect("registry parses");
    let client = AuthClient::new(registry, MemoryStore::new());

    let auth = client
        .begin_device("test")
        .await
        .expect("begin_device returns a DeviceAuthorization");
    assert_eq!(auth.user_code, "ABCD-1234");

    let credential = client
        .complete_device(auth, Duration::from_secs(5))
        .await
        .expect("complete_device polls until a token is available");

    assert_eq!(credential.provider(), "test");
    assert_eq!(credential.secret(), Some("device-access-token"));
    assert_eq!(credential.token_type().map(|s| s.as_str()), Some("Bearer"));
}

#[test]
fn pkce_verifier_is_url_safe_and_within_rfc_range() {
    use crate::generate_pkce;

    let pkce = generate_pkce();
    let len = pkce.code_verifier.len();
    assert!(
        (43..=128).contains(&len),
        "verifier length {len} not in 43..=128"
    );

    let url_safe = pkce
        .code_verifier
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_');
    assert!(
        url_safe,
        "verifier contains non-URL-safe characters: {}",
        pkce.code_verifier
    );
    assert!(
        !pkce.code_verifier.ends_with('='),
        "verifier must not be base64 padded"
    );
}

#[test]
fn pkce_challenge_is_s256_of_verifier() {
    use base64::Engine;
    use sha2::Digest;
    use sha2::Sha256;

    use crate::generate_pkce;

    let pkce = generate_pkce();
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(pkce.code_verifier.as_bytes()));
    assert_eq!(
        pkce.code_challenge, expected,
        "challenge is SHA256(verifier) base64"
    );
}

#[test]
fn pkce_state_is_url_safe_and_non_empty() {
    use crate::generate_state;

    let state = generate_state();
    assert!(!state.is_empty(), "state must not be empty");
    let url_safe = state
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_');
    assert!(url_safe, "state contains non-URL-safe characters: {state}");
    assert!(!state.ends_with('='), "state must not be base64 padded");
}

#[test]
fn pkce_codes_debug_redacts_verifier() {
    use crate::generate_pkce;

    let pkce = generate_pkce();
    let rendered = format!("{pkce:?}");
    assert!(
        rendered.contains("code_verifier: \"<redacted>\""),
        "Debug must hide verifier: {rendered}"
    );
    assert!(
        !rendered.contains(&pkce.code_verifier),
        "Debug must not leak the verifier value: {rendered}"
    );
    assert!(
        rendered.contains(&pkce.code_challenge),
        "Debug may show the public challenge: {rendered}"
    );
}

#[test]
fn auth_client_and_memory_store_are_clone() {
    use crate::AuthClient;

    let client = AuthClient::builtin(MemoryStore::new()).expect("built-in registry parses");
    let client2 = client.clone();

    // Stores are independent copies: a write to one does not affect the other.
    let cred = Credential::api_key("anthropic", "sk-ant-test".to_string());
    client.store().put(&cred).expect("put on original");
    assert!(
        client2.store().get("anthropic").unwrap().is_none(),
        "cloned store is independent"
    );

    // MemoryStore itself can be cloned directly and is independent.
    let store = MemoryStore::new();
    let store2 = store.clone();
    store.put(&cred).expect("put on original store");
    assert!(
        store2.get("anthropic").unwrap().is_none(),
        "cloned MemoryStore is independent"
    );
}

#[tokio::test]
async fn oidc_discovery_builds_an_oauth_config_from_the_well_known_document() {
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use crate::discovery::discover;

    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "device_authorization_endpoint": format!("{issuer}/device"),
            "revocation_endpoint": format!("{issuer}/revoke"),
            "scopes_supported": ["openid", "profile", "email"],
            "code_challenge_methods_supported": ["S256"],
            // An unknown field must be ignored, not rejected.
            "unknown_provider_extension": true,
        })))
        .mount(&server)
        .await;

    let metadata = discover(&issuer).await.expect("discovery document parses");
    assert_eq!(
        metadata.authorization_endpoint,
        format!("{issuer}/authorize")
    );
    assert_eq!(metadata.token_endpoint, format!("{issuer}/token"));
    assert_eq!(
        metadata.device_authorization_endpoint.as_deref(),
        Some(format!("{issuer}/device").as_str())
    );
    assert_eq!(
        metadata.revocation_endpoint.as_deref(),
        Some(format!("{issuer}/revoke").as_str())
    );

    let config = metadata.to_oauth_config("my-client", vec!["openid".to_string()]);
    assert_eq!(config.authorize_url, format!("{issuer}/authorize"));
    assert_eq!(config.token_url, format!("{issuer}/token"));
    assert_eq!(config.client_id, "my-client");
    assert_eq!(config.scopes, vec!["openid".to_string()]);
}

#[tokio::test]
async fn oidc_discovery_rejects_an_issuer_mismatch() {
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use crate::Error;
    use crate::discovery::discover;

    let server = MockServer::start().await;
    let issuer = server.uri();
    // The document claims a DIFFERENT issuer than the one fetched (mix-up attack).
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": "https://evil.example.com",
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
        })))
        .mount(&server)
        .await;

    let err = discover(&issuer)
        .await
        .expect_err("an issuer mismatch must fail loud, never yield a config");
    match err {
        Error::Malformed(detail) => assert!(
            detail.contains("issuer mismatch"),
            "detail explains the mismatch: {detail}"
        ),
        other => panic!("expected Error::Malformed, got {other:?}"),
    }
}

#[tokio::test]
async fn oidc_discovery_rejects_a_malformed_document_and_a_missing_endpoint() {
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use crate::Error;
    use crate::discovery::discover;

    // Not JSON at all.
    let bad_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
        .mount(&bad_server)
        .await;
    let err = discover(&bad_server.uri())
        .await
        .expect_err("a non-JSON discovery body must be rejected");
    assert!(matches!(err, Error::Malformed(_)), "got {err:?}");

    // Valid JSON but missing the required token_endpoint.
    let partial_server = MockServer::start().await;
    let issuer = partial_server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            // token_endpoint intentionally omitted.
        })))
        .mount(&partial_server)
        .await;
    let err = discover(&issuer)
        .await
        .expect_err("a discovery document without token_endpoint must be rejected");
    assert!(matches!(err, Error::Malformed(_)), "got {err:?}");
}

#[tokio::test]
async fn oidc_discovery_fails_loud_on_a_non_success_status() {
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use crate::Error;
    use crate::discovery::discover;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let err = discover(&server.uri())
        .await
        .expect_err("a 404 discovery endpoint must fail, never a guessed config");
    match err {
        Error::Authorization(detail) => {
            assert!(detail.contains("404"), "detail carries status: {detail}")
        }
        other => panic!("expected Error::Authorization, got {other:?}"),
    }
}

#[tokio::test]
async fn oidc_discovery_normalizes_a_trailing_slash_on_the_issuer() {
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use crate::discovery::discover;

    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        // The path must be exactly the well-known path, with no doubled slash.
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
        })))
        .mount(&server)
        .await;

    // Pass the issuer WITH a trailing slash; discovery must normalize it.
    let with_slash = format!("{issuer}/");
    let metadata = discover(&with_slash)
        .await
        .expect("a trailing slash on the issuer is normalized, not doubled");
    assert_eq!(metadata.token_endpoint, format!("{issuer}/token"));
}

#[cfg(feature = "encrypted-store")]
#[test]
fn encrypted_store_roundtrips_and_never_stores_plaintext() {
    use crate::CredentialStore;
    use crate::EncryptedStore;

    let store = EncryptedStore::new([7u8; 32]);
    let secret = "super-secret-access-token-value";
    let cred = Credential::oauth(
        "acme",
        secret.to_string(),
        Some("refresh-xyz".into()),
        Some(9_999),
        None,
    );

    store.put(&cred).expect("put seals the credential");

    // Round-trip: what comes back decrypts to exactly what went in.
    let loaded = store
        .get("acme")
        .expect("get succeeds")
        .expect("credential present");
    assert_eq!(loaded, cred);
    assert_eq!(loaded.secret(), Some(secret));
    assert!(
        !format!("{loaded:?}").contains(secret),
        "Debug stays redacted after decrypt"
    );

    // The at-rest bytes are ciphertext: neither the access token nor the refresh
    // token may appear in the sealed byte string a caller would write to disk.
    let sealed = store.seal(&cred).expect("seal produces bytes");
    let sealed_str = String::from_utf8_lossy(&sealed);
    assert!(
        !sealed_str.contains(secret),
        "access token leaked into ciphertext"
    );
    assert!(
        !sealed_str.contains("refresh-xyz"),
        "refresh token leaked into ciphertext"
    );
    // AEAD framing: nonce (12) + tag (16) overhead beyond the plaintext.
    let plaintext_len = serde_json::to_vec(&cred).unwrap().len();
    assert!(
        sealed.len() >= plaintext_len + 12 + 16,
        "sealed length {} must cover the 12-byte nonce and 16-byte tag over {plaintext_len} plaintext bytes",
        sealed.len()
    );

    // providers() and delete() behave like any store.
    assert_eq!(store.providers().unwrap(), vec!["acme".to_string()]);
    store.delete("acme").expect("delete is idempotent");
    assert_eq!(store.get("acme").unwrap(), None);
    assert_eq!(store.providers().unwrap(), Vec::<String>::new());
}

#[cfg(feature = "encrypted-store")]
#[test]
fn encrypted_store_wrong_key_fails_and_nonces_are_fresh() {
    use crate::EncryptedStore;

    let secret = "PLAINTEXT-TOKEN-must-be-encrypted";
    let cred = Credential::api_key("openai", secret.to_string());

    let sealed = EncryptedStore::new([42u8; 32]).seal(&cred).expect("seal");

    // A store built with a DIFFERENT key cannot open the sealed bytes (authenticated
    // decryption fails closed; it never returns a guessed credential).
    let err = EncryptedStore::new([43u8; 32])
        .open(&sealed)
        .expect_err("a wrong key must fail, never yield the credential");
    assert!(matches!(err, crate::Error::Store(_)), "got {err:?}");

    // The correct key opens it.
    let opened = EncryptedStore::new([42u8; 32])
        .open(&sealed)
        .expect("right key opens");
    assert_eq!(opened.secret(), Some(secret));

    // Tampering with the ciphertext is detected (flip one byte in the tag region).
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        EncryptedStore::new([42u8; 32]).open(&tampered).is_err(),
        "a tampered tag must fail authentication"
    );

    // A fresh random nonce per seal makes two seals of the same credential differ.
    let a = EncryptedStore::new([42u8; 32]).seal(&cred).unwrap();
    let b = EncryptedStore::new([42u8; 32]).seal(&cred).unwrap();
    assert_ne!(a, b, "each seal must use a fresh nonce");
}
