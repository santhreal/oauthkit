# Changelog

All notable changes to `oauthkit` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2026-08-07

### Fixed
- Reject authorization-code redirects that carry a code but omit `state`, treating missing `state` as `Error::StateMismatch` instead of a stray probe.
- Preserve and format `error_description` alongside `error` in authorization-code error redirects (`{error}: {error_description}`).
- Validate token response access tokens and token types in `post_token_form`, failing loud with `Error::Malformed` on empty or whitespace-only values.
- Validate non-empty required fields (`device_code`, `user_code`, `verification_uri`) in device authorization responses, failing loud on empty values.
- Enforce URL validation (HTTPS requirement for remote endpoints) on OIDC discovery endpoints (`authorization_endpoint`, `token_endpoint`, `device_authorization_endpoint`).

### Security
- Reserved OAuth protocol query parameter collision list in `build_authorize_url` expanded to include `audience`, `prompt`, and `login_hint`.

### Changed
- Standardized Cargo.toml `authors` to `Santh <64453045+santhreal@users.noreply.github.com>`.
## [0.2.2] - 2026-08-06

### Security
- Compare authorization-code anti-CSRF `state` with constant-time equality.
- Reject `extra_authorize_params` keys that collide with reserved OAuth protocol parameters instead of silently dropping them after typed params win.

### Fixed
- Fixed redirect loopback binding now matches the redirect URI host family (`127.0.0.1` / `::1`) with cross-family fallback.

### Changed
- Declared `package.metadata.santh.status = "beta"` (no fuzz target yet; not `stable`).

## [0.2.1] - 2026-07-30

### Security
- `TokenResponse` and `DeviceAuthorizationResponse` no longer derive `Debug`: the derived impl would have printed live access/refresh tokens and device codes into any `{:?}` log (CWE-532). Manual Debug impls now redact secrets and show shape only.
- Registry validation now requires `https` for authorize/token/device-authorization endpoints (CWE-319); plain `http` is accepted only to loopback hosts (`127.0.0.1`, `localhost`, `::1`) for local development and in-process test servers.

### Fixed
- `EncryptedStore` operations (`put`, `get`, `delete`, `providers`) no longer panic on a poisoned lock; they return `Error::Store`, matching `MemoryStore`. The read-only `sealed_len` probe recovers the guard instead of unwrapping.

## [0.2.0] - 2026-07-14

### Fixed
- The ephemeral loopback redirect server now prefers IPv4 (`127.0.0.1`) and falls
  back to IPv6 (`[::1]`), keeping the redirect URI host coherent with whichever
  family actually bound. Previously it bound `127.0.0.1` only, failing on
  IPv6-only-localhost hosts.
- Token-expiry math no longer overflows on a hostile or buggy provider
  `expires_in`. It is parsed straight from the token response, so an `i64::MAX` /
  `i64::MIN` value used to panic (debug) or wrap to a nonsensical expiry (release);
  the absolute expiry is now computed with a saturating add.
- Device-code polling now honors `max_wait` regardless of the server-advertised
  `interval`. Each poll sleep is bounded by the time left until the deadline, so a
  hostile or buggy provider returning a huge `interval` can no longer hang the
  sign-in far past the caller's timeout.
- The loopback redirect handler no longer aborts a sign-in on a stray request. A
  request carrying only a `state` param (no authorization code) is ignored rather
  than treated as a state mismatch, so a probe to the ephemeral callback port can
  no longer cancel an in-progress sign-in. A real redirect with a mismatched state
  still fails loud, so CSRF protection is unchanged.

### Added
- Standalone crate metadata: Apache-2.0 `LICENSE`, `CHANGELOG.md`, `SPEC.md`,
  `deny.toml`, and `rust-toolchain.toml`.
- Typed `OAuthConfig` fields `audience`, `prompt`, and `login_hint` that merge
  into the authorize URL, alongside `extra_authorize_params` for custom keys. A
  custom extra whose key collides with a typed/protocol parameter OR with an
  earlier custom entry is dropped (first occurrence wins), so the authorize URL
  never carries a duplicate query key. A property test fuzzes the builder with
  arbitrary hostile keys/values to lock this invariant.
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
- **Breaking:** `OAuthConfig` is now `#[non_exhaustive]` and derives `Default`, and
  gains an `OAuthConfig::new(authorize_url, token_url, client_id)` constructor.
  Construct it via `new` (then set the optional fields) instead of a struct literal;
  future provider knobs can then be added as compatible releases. Registry/TOML and
  `OidcMetadata::to_oauth_config` construction are unaffected.
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

[Unreleased]: https://github.com/santhreal/oauthkit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/santhreal/oauthkit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/santhreal/oauthkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/santhreal/oauthkit/releases/tag/v0.1.0
