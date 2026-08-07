# oauthkit — specification

`oauthkit` is a provider-registry-driven OAuth SDK for command-line tools. It
turns a declarative description of a provider's sign-in methods into working
authorization-code (with PKCE), device-code, and API-key flows, and stores the
resulting credentials behind a pluggable trait.

## Scope

- **In scope:** describing providers and their sign-in methods; executing the
  three sign-in flows; parsing and validating token/error responses; holding
  credentials behind a `CredentialStore`; redacting secrets in `Debug`.
- **Out of scope:** deciding *which* provider a user should use, refreshing on a
  schedule, and any UI. The crate is display/selection-agnostic. Persistence is a
  caller-supplied `CredentialStore`; the opt-in `encrypted-store` feature adds an
  `EncryptedStore` that seals credentials with ChaCha20-Poly1305 under a
  caller-supplied key (its `seal`/`open` bytes can be written to disk or a keyring).

## Data model

- `Registry` — a validated set of `Provider`s, loaded from TOML (`rules/`) or
  constructed programmatically. `Registry::validate` rejects malformed
  `authorize_url` / `token_url` / `device_authorization_url` / `redirect_uri`,
  a `loopback_port` that conflicts with an explicit `redirect_uri` port, and
  more than one `AuthMethod` of the same kind per provider.
- `Provider` — an id plus one or more `AuthMethod`s (`OAuthConfig`,
  `DeviceCodeConfig`, `ApiKeyConfig`). `oauth()`, `device()`, and `api_key()`
  return the first method of that kind; validation guarantees uniqueness, so
  first-match is deterministic.
- `OAuthConfig` — the authorization-code + PKCE parameters (`authorize_url`,
  `token_url`, `client_id`, `scopes`) plus typed optional authorize params
  (`audience`, `prompt`, `login_hint`), `redirect_uri` / `loopback_port`, and
  `extra_authorize_params` for provider-specific keys (a custom key that collides
  with one oauthkit already emits, including a typed field, is dropped). The type
  is `#[non_exhaustive]` and derives `Default`; construct it with
  `OAuthConfig::new(authorize_url, token_url, client_id)` and set the optional
  fields on the returned value so new knobs can be added as compatible releases.
- `Credential` — an enum with `OAuth { access_token, refresh_token?,
  token_type, .. }` and `ApiKey { key }` variants. The type enforces a valid
  shape; `secret()` returns the sensitive material and `Debug` is redacted.

## Flows

- **Authorization code + PKCE** (`AuthClient::begin_oauth` → `BeganAuthorization`):
  generates a PKCE verifier/challenge and `state`, opens a loopback redirect
  server bound to `loopback_port` (or an ephemeral port when `0`), rewrites port
  `0` in the authorize URL to the actually bound port, and matches the callback
  on the path taken from the configured `redirect_uri`. `state` mismatch is a
  hard error.
- **Device code** (`begin_device` → `complete_device`): requests a device code,
  then polls the token endpoint honoring `slow_down` (increase interval) and
  terminating on `access_denied` / `expired_token`. `complete_device` bounds the
  wait by `DEFAULT_SIGN_IN_TIMEOUT` (or a caller value).
- **API key** (`accept_api_key`, `api_key_from_env`): validates and wraps a
  caller-supplied key; no network call.
- **OIDC discovery** (`discover` → `OidcMetadata::to_oauth_config`): fetches
  `<issuer>/.well-known/openid-configuration`, validates it (non-2xx, malformed,
  or an issuer mismatch all fail loud), and turns the discovered endpoints plus a
  caller-supplied client id and scopes into an `OAuthConfig`.

## Guarantees

- **Fail closed / fail loud:** token and error responses parse into structured
  types; non-2xx bodies are parsed for `error` / `error_description`. Missing or
  malformed data is an `Error`, never a silently-empty `Credential`.
- **Secret hygiene:** no secret appears in `Debug`, `Display`, or (per row 15)
  tracing output. `secret()` is the single accessor.
- **Timeouts:** the HTTP client sets connect/read timeouts so a hung provider
  endpoint cannot block a flow indefinitely.
- **Deterministic dependencies:** every dependency is a concrete version; the
  crate compiles standalone (edition 2024, consumer MSRV Rust 1.86 set by the
  `icu`/`idna` dependency floor) with no workspace inheritance. The full test
  suite additionally needs Rust 1.88 (the `wiremock` dev-dependency uses
  let-chains); the pinned `rust-toolchain.toml` reflects that development floor.

## Public API

`Registry`, `Provider`, `AuthMethod`, `OAuthConfig`, `DeviceCodeConfig`,
`ApiKeyConfig`; `AuthClient<S: CredentialStore>` with `builtin` / `new`,
`begin_oauth`, `begin_device`, `complete_device`, `accept_api_key`,
`api_key_from_env`, `refresh_stored`, `logout`; `Credential`, `CredentialKind`,
`CredentialStore`, `MemoryStore`; `PkceCodes`, `generate_pkce`, `generate_state`, `constant_time_eq`;
`discover`, `OidcMetadata`; `Error`, `Result`; `DEFAULT_SIGN_IN_TIMEOUT`. Behind
the `encrypted-store` feature: `EncryptedStore`.

## Stability

Pre-1.0: the API may change between minor versions. Changes are recorded in
`CHANGELOG.md`. Credential serialization is tagged so stored credentials remain
readable across compatible versions.
