//! API-key sign-in: the simplest method, plus the small conveniences a CLI wants
//! around it (env pickup and a cheap client-side shape check).

use crate::credentials::Credential;
use crate::error::Error;
use crate::error::Result;
use crate::provider::ApiKeyConfig;

/// Read the provider's API key from its configured environment variable, if the
/// provider declares one and it is set and non-empty.
pub fn from_env(config: &ApiKeyConfig) -> Option<String> {
    let var = config.env_var.as_deref()?;
    match std::env::var(var) {
        // Trim to match `accept`: a key exported as `KEY=$(cat file)` carries a trailing newline,
        // and returning it verbatim would fail auth for whitespace the interactive path strips.
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

/// Accept a user-entered API key into a [`Credential`], applying only a cheap
/// client-side sanity check (non-empty, and matching the declared prefix when
/// one exists). This never validates against the provider: that is the caller's
/// job on first real use, and failing here would be a silent gate.
pub fn accept(provider: &str, config: &ApiKeyConfig, key: &str) -> Result<Credential> {
    let key = key.trim();
    if key.is_empty() {
        return Err(Error::Malformed("API key was empty".into()));
    }
    if let Some(prefix) = &config.key_prefix {
        if !key.starts_with(prefix) {
            return Err(Error::Malformed(format!(
                "API key does not start with the expected `{prefix}` prefix"
            )));
        }
    }
    Ok(Credential::api_key(provider.to_string(), key.to_string()))
}
