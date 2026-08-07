//! An opt-in [`CredentialStore`] that encrypts credentials at rest.
//!
//! Enabled by the `encrypted-store` feature. [`EncryptedStore`] serializes each
//! [`Credential`] to JSON and seals it with ChaCha20-Poly1305 (a pure-Rust AEAD,
//! no system dependencies) under a caller-supplied 32-byte key and a fresh random
//! nonce. Only the ciphertext is ever held, so the plaintext token never resides
//! in the store's backing.
//!
//! This built-in keeps the sealed bytes in memory; the bytes are exactly what a
//! caller would persist to disk (see [`EncryptedStore::sealed_len`] for the
//! at-rest size). Swap the backing for files or a keyring by wrapping the same
//! seal/open helpers if durable storage is needed.

use std::collections::HashMap;
use std::sync::Mutex;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::Key;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;
use chacha20poly1305::aead::Aead;
use rand::RngCore;

use crate::credentials::Credential;
use crate::credentials::CredentialStore;
use crate::error::Error;
use crate::error::Result;

/// The ChaCha20-Poly1305 nonce size (RFC 8439: 96 bits).
const NONCE_LEN: usize = 12;

/// A [`CredentialStore`] that encrypts every credential at rest with a
/// caller-supplied key.
///
/// The key is 32 bytes; derive it from a passphrase (e.g. Argon2) or a random
/// device key before constructing the store. A random nonce is generated per
/// write, so encrypting the same credential twice yields different ciphertext.
pub struct EncryptedStore {
    cipher: ChaCha20Poly1305,
    // provider id -> sealed bytes (nonce || ciphertext+tag). This is the exact
    // byte string a caller would write to disk.
    sealed: Mutex<HashMap<String, Vec<u8>>>,
}

impl EncryptedStore {
    /// Create an encrypted store from a 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        Self {
            cipher,
            sealed: Mutex::new(HashMap::new()),
        }
    }

    /// The number of sealed (encrypted) bytes currently held for `provider`, if
    /// any. Useful to prove data is stored without exposing plaintext.
    pub fn sealed_len(&self, provider: &str) -> Option<usize> {
        // Read-only probe: a poisoned lock still holds consistent map state, so
        // recover the guard instead of panicking or hiding the entry.
        let guard = match self.sealed.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(provider).map(Vec::len)
    }

    /// Encrypt a credential into a self-contained sealed byte string
    /// (`nonce || ciphertext || tag`). Exposed so a caller can persist the bytes
    /// themselves (e.g. to a file or keyring) instead of using the in-memory
    /// backing. Reverse with [`open`](Self::open).
    pub fn seal(&self, credential: &Credential) -> Result<Vec<u8>> {
        let plaintext = serde_json::to_vec(credential)
            .map_err(|e| Error::Store(format!("could not serialize credential: {e}")))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|_| Error::Store("credential encryption failed".to_string()))?;
        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Decrypt and deserialize a credential sealed by [`seal`](Self::seal).
    /// Fails on a wrong key, a truncated buffer, or tampered bytes (authenticated
    /// decryption); it never returns a partial or guessed credential.
    pub fn open(&self, sealed: &[u8]) -> Result<Credential> {
        if sealed.len() < NONCE_LEN {
            return Err(Error::Store("sealed credential is truncated".to_string()));
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        // A wrong key or tampered bytes fail here (authenticated decryption); we
        // never return a partial or guessed credential.
        let plaintext = self.cipher.decrypt(nonce, ciphertext).map_err(|_| {
            Error::Store("credential decryption failed (wrong key or tampered data)".to_string())
        })?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Store(format!("could not deserialize credential: {e}")))
    }
    #[cfg(test)]
    pub(crate) fn poison_lock_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.sealed.lock();
            panic!("poisoning the store lock for the poisoned-lock regression test");
        }));
    }
}

impl CredentialStore for EncryptedStore {
    fn put(&self, credential: &Credential) -> Result<()> {
        let sealed = self.seal(credential)?;
        self.sealed
            .lock()
            .map_err(|_| Error::Store("encrypted store lock poisoned".into()))?
            .insert(credential.provider().to_string(), sealed);
        Ok(())
    }

    fn get(&self, provider: &str) -> Result<Option<Credential>> {
        let sealed = self
            .sealed
            .lock()
            .map_err(|_| Error::Store("encrypted store lock poisoned".into()))?
            .get(provider)
            .cloned();
        match sealed {
            Some(bytes) => Ok(Some(self.open(&bytes)?)),
            None => Ok(None),
        }
    }

    fn delete(&self, provider: &str) -> Result<()> {
        self.sealed
            .lock()
            .map_err(|_| Error::Store("encrypted store lock poisoned".into()))?
            .remove(provider);
        Ok(())
    }

    fn providers(&self) -> Result<Vec<String>> {
        let mut providers: Vec<String> = self
            .sealed
            .lock()
            .map_err(|_| Error::Store("encrypted store lock poisoned".into()))?
            .keys()
            .cloned()
            .collect();
        providers.sort();
        Ok(providers)
    }
}
