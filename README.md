# oauthkit

A provider-registry-driven OAuth SDK for command-line tools. It gives any CLI the
breadth of model-provider sign-in without hard-coding a single provider.

## What it does

- **Three flows, one token path.** Authorization-code with PKCE (loopback
  redirect), device-code (RFC 8628), and API-key. Success and error parsing live
  in one shared token path.
- **Data-driven provider registry.** Providers are declared as data in
  `rules/providers.toml`. Extend the set by merging your own TOML, not by editing
  the crate.
- **UI-agnostic.** The SDK returns authorize URLs, device user codes, and
  `Credential`s. Your CLI owns all rendering.
- **Pluggable storage.** Persistence is a `CredentialStore` you supply; a
  `MemoryStore` ships for tests.
- **No silent fallback.** Every flow fails loud: a state mismatch, an OAuth
  error, or a timeout returns an `Error`, never a degraded success. Tokens are
  redacted in `Debug` output.

The built-in registry currently ships API-key and device-code providers. OAuth
providers must be added by merging your own TOML (see `Extending the registry`
below). The SDK still implements the authorization-code flow for any provider
that you configure.

## Usage

```rust,no_run
use oauthkit::{AuthClient, CredentialStore, MemoryStore};
use std::time::Duration;

# async fn run() -> oauthkit::Result<()> {
let client = AuthClient::builtin(MemoryStore::new())?;

// List providers to build a picker.
for provider in client.providers() {
    println!("{} ({})", provider.display_name, provider.id);
}

// Device-code sign-in (the built-in registry ships a GitHub Copilot device flow).
let begun = client.begin_device("github-copilot").await?;
println!("Open {} and enter {}", begun.verification_uri, begun.user_code);
let credential = begun.poll(Duration::from_secs(300)).await?;
client.store().put(&credential)?;

// API-key sign-in.
let cred = client.accept_api_key("anthropic", "sk-ant-...")?;
client.store().put(&cred)?;
# Ok(())
# }
```

## Extending the registry

Add providers or override built-ins as data:

```rust
use oauthkit::Registry;

# let my_toml = r#"
# [[provider]]
# id = "acme"
# display_name = "Acme"
# [[provider.methods]]
# flow = "api_key"
# "#;
let mut registry = Registry::builtin()?;
registry.merge(Registry::from_toml(my_toml)?); // later id wins
# Ok::<(), oauthkit::Error>(())
```

## Adding an OAuth provider

The built-ins are API-key and device-code because those work with a public,
non-secret identifier. Authorization-code OAuth needs a `client_id` **you**
register with the provider, so you supply it as data. Declare an `oauth` method in
your own TOML and merge it:

```toml
[[provider]]
id = "acme"
display_name = "Acme"

[[provider.methods]]
flow = "oauth"
authorize_url = "https://auth.acme.example/authorize"
token_url = "https://auth.acme.example/oauth/token"
client_id = "your-registered-client-id"
scopes = ["openid", "profile", "offline_access"]
# Typed, well-known authorize parameters (merged into the authorize URL):
audience = "https://api.acme.example"
prompt = "consent"
# Anything else the provider needs that has no typed field:
extra_authorize_params = [["custom_toggle", "1"]]
```

To build a config in code, use `OAuthConfig::new` (the type is `#[non_exhaustive]`,
so set the optional fields on the returned value rather than a struct literal):

```rust
use oauthkit::OAuthConfig;

let mut oauth = OAuthConfig::new(
    "https://auth.acme.example/authorize",
    "https://auth.acme.example/oauth/token",
    "your-registered-client-id",
);
oauth.scopes = vec!["openid".into(), "profile".into()];
oauth.audience = Some("https://api.acme.example".into());
```

If the provider publishes an OpenID Connect discovery document, let oauthkit read
the endpoints instead of hand-copying them:

```rust,no_run
use oauthkit::discover;

# async fn run() -> oauthkit::Result<()> {
let metadata = discover("https://auth.acme.example").await?;
let oauth = metadata.to_oauth_config("your-registered-client-id", vec!["openid".into()]);
// `oauth` is an `OAuthConfig` you can put in a `Provider`/`Registry`.
# let _ = oauth;
# Ok(())
# }
```

Store credentials encrypted at rest with the optional `encrypted-store` feature
(pure-Rust ChaCha20-Poly1305 under a 32-byte key you supply):

```toml
oauthkit = { version = "0.2", features = ["encrypted-store"] }
```

## License

Apache-2.0.
