//! PKCE (RFC 7636) helpers for the authorization-code flow.

use base64::Engine;
use rand::RngCore;
use sha2::Digest;
use sha2::Sha256;

/// A PKCE verifier/challenge pair for one authorization request.
#[derive(Clone)]
pub struct PkceCodes {
    /// The secret verifier, sent only on the back-channel token exchange.
    pub code_verifier: String,
    /// The public S256 challenge, sent on the front-channel authorize request.
    pub code_challenge: String,
}

impl std::fmt::Debug for PkceCodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `code_verifier` is the PKCE secret proving the auth-request origin;
        // logging it (CWE-532) would weaken the flow. `code_challenge` is the
        // public hash sent to the authorization server, so it stays visible.
        f.debug_struct("PkceCodes")
            .field("code_verifier", &"<redacted>")
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

/// Generate a fresh S256 PKCE pair.
pub fn generate_pkce() -> PkceCodes {
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);

    // Verifier: URL-safe base64 without padding (43..128 chars).
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    // Challenge (S256): BASE64URL-ENCODE(SHA256(verifier)) without padding.
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);

    PkceCodes {
        code_verifier,
        code_challenge,
    }
}

/// Generate an opaque, URL-safe anti-CSRF `state` value.
pub fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
