//! Error type for the SDK. One error enum, one place.

/// Everything that can go wrong during provider discovery or a sign-in flow.
///
/// Variants stay coarse on purpose: a consuming CLI renders them to the user, so
/// each carries enough context to explain itself without leaking secrets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The provider registry data (TOML) could not be parsed.
    #[error("invalid provider registry: {0}")]
    Registry(String),

    /// A provider id was requested that the registry does not define.
    #[error("unknown provider `{0}`")]
    UnknownProvider(String),

    /// The provider does not offer the requested authentication method.
    #[error("provider `{provider}` does not support {method} sign-in")]
    UnsupportedMethod {
        /// The provider id.
        provider: String,
        /// The method that was requested (`oauth`, `device`, `api_key`).
        method: &'static str,
    },

    /// A network request failed.
    #[error("network error: {0}")]
    Http(String),

    /// The authorization server returned an error response (RFC 6749 §5.2 /
    /// §3.1.2.6). The string is the server-provided `error` code plus any
    /// `error_description`, never a token.
    #[error("authorization server rejected the request: {0}")]
    Authorization(String),

    /// The OAuth redirect returned a `state` that did not match the one we sent,
    /// which means the response cannot be trusted (possible CSRF).
    #[error("sign-in aborted: the authorization response did not match this request")]
    StateMismatch,

    /// The loopback redirect listener could not be started or accepted.
    #[error("could not run the local sign-in listener: {0}")]
    Loopback(String),

    /// The device-code flow was still pending when the deadline elapsed.
    #[error("sign-in timed out waiting for authorization")]
    Timeout,

    /// The user (or the authorization server) cancelled the flow.
    #[error("sign-in was cancelled")]
    Cancelled,

    /// A token or discovery response was missing a required field.
    #[error("malformed authorization response: {0}")]
    Malformed(String),

    /// A credential store operation failed.
    #[error("credential store error: {0}")]
    Store(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Http(err.to_string())
    }
}
