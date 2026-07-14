# Changelog

All notable changes to `oauthkit` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Standalone crate metadata: Apache-2.0 `LICENSE`, `CHANGELOG.md`, `SPEC.md`,
  `deny.toml`, and `rust-toolchain.toml`.
- Typed `OAuthConfig` fields `audience`, `prompt`, and `login_hint` that merge
  into the authorize URL, alongside `extra_authorize_params` for custom keys. A
  custom extra that collides with a typed or protocol parameter is dropped so the
  authorize URL never carries a duplicate query key.
- `tracing` instrumentation on the authorization-code, device-code, and refresh
  flows (`#[tracing::instrument(skip_all)]` with only non-secret fields). A test
  captures the span/event output and asserts no token material is ever logged.
- OpenID Connect discovery: `discover(issuer)` fetches and validates
  `<issuer>/.well-known/openid-configuration`, and `OidcMetadata::to_oauth_config`
  builds an `OAuthConfig` from the discovered endpoints plus a caller-supplied
  client id and scopes. Discovery fails loud on a non-2xx status, a malformed
  document, or an issuer mismatch (Discovery §4.3 mix-up defense).
- Opt-in `encrypted-store` feature: `EncryptedStore` is a `CredentialStore` that
  seals credentials at rest with ChaCha20-Poly1305 under a caller-supplied 32-byte
  key and a fresh per-write nonce. Public `seal`/`open` let a caller persist the
  ciphertext to disk or a keyring; a wrong key or tampered bytes fail closed.
- README section documenting how to add an authorization-code OAuth provider
  (BYO `client_id` via TOML, or via OIDC discovery).
- README examples are compiled as doctests (`#[doc = include_str!("../README.md")]`)
  so documentation cannot drift from the public API.
- GitHub Actions CI (`.github/workflows/ci.yml`): format check, `clippy -D warnings`,
  `cargo test --all-features`, doc tests, a 1.86 MSRV `--lib` build, and `cargo deny`.

### Changed
- `Credential::is_expired` uses `is_some_and`; a redirect-URI validation error and
  a few call sites use inlined format arguments (clippy-clean, no behavior change).

## [0.1.0] - 2026-07-13

Initial extraction of `oauthkit` from the `veyyon-code` workspace into a
standalone, provider-registry-driven OAuth SDK for CLIs.

### Added
- Provider registry (`Registry`, `Provider`) describing OAuth authorization-code,
  device-code, and API-key sign-in methods, loaded from TOML data files.
- `AuthClient` over a pluggable `CredentialStore` (`MemoryStore` built in),
  with `begin_device` / `complete_device` and method-dispatch sign-in.
- Authorization-code + PKCE flow with a loopback redirect server that honors the
  configured `redirect_uri` path and rewrites port `0` to the actually bound port.
- Device-code flow with `slow_down` / `access_denied` handling and structured
  OAuth error parsing.
- `Credential` as a shape-enforcing enum (`OAuth` / `ApiKey`) with `Debug`
  redaction and a `secret()` accessor.
- Registry validation rejecting malformed URLs, redirect-scheme/port conflicts,
  and duplicate methods of the same kind per provider.
- HTTP client timeouts and structured `TokenErrorResponse` parsing on non-2xx.

### Changed
- All dependencies pinned to concrete versions (no workspace inheritance);
  `anyhow` removed.

[Unreleased]: https://github.com/santhreal/oauthkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/santhreal/oauthkit/releases/tag/v0.1.0
