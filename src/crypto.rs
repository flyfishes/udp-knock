use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 12;
const HMAC_LEN: usize = 32;
const REPLAY_WINDOW_SECS: u64 = 30;

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    Base64DecodeError,
    PacketTooShort,
    HmacMismatch,
    DecryptionFailed,
    TimestampExpired,
    InvalidTimestamp,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Base64DecodeError => write!(f, "Base64 decode error"),
            CryptoError::PacketTooShort => write!(f, "Packet payload too short"),
            CryptoError::HmacMismatch => write!(f, "HMAC verification failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::TimestampExpired => write!(f, "Timestamp window expired"),
            CryptoError::InvalidTimestamp => write!(f, "Invalid timestamp format"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub struct CryptoManager {
    aes_key: [u8; 32],
    hmac_key: [u8; 32],
}

impl CryptoManager {
    pub fn new(shared_key: &str) -> Self {
        // Derive AES key
        let mut hasher_aes = Sha256::new();
        hasher_aes.update(shared_key.as_bytes());
        hasher_aes.update(b":aes-key");
        let aes_key: [u8; 32] = hasher_aes.finalize().into();

        // Derive HMAC key
        let mut hasher_hmac = Sha256::new();
        hasher_hmac.update(shared_key.as_bytes());
        hasher_hmac.update(b":hmac-key");
        let hmac_key: [u8; 32] = hasher_hmac.finalize().into();

        Self { aes_key, hmac_key }
    }

    /// Encrypt plaintext into Base64 encoded payload: [Nonce(12B) | HMAC(32B) | Ciphertext]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher =
            Aes256Gcm::new_from_slice(&self.aes_key).map_err(|_| CryptoError::DecryptionFailed)?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Compute HMAC over nonce + ciphertext
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key)
            .map_err(|_| CryptoError::HmacMismatch)?;
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        let hmac_result = mac.finalize().into_bytes();

        let mut buffer = Vec::with_capacity(NONCE_LEN + HMAC_LEN + ciphertext.len());
        buffer.extend_from_slice(&nonce_bytes);
        buffer.extend_from_slice(&hmac_result);
        buffer.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(buffer))
    }

    /// Decrypt Base64 encoded payload back into plaintext after verifying HMAC
    pub fn decrypt(&self, base64_payload: &str) -> Result<Vec<u8>, CryptoError> {
        let raw_bytes = BASE64
            .decode(base64_payload.trim())
            .map_err(|_| CryptoError::Base64DecodeError)?;

        if raw_bytes.len() < NONCE_LEN + HMAC_LEN {
            return Err(CryptoError::PacketTooShort);
        }

        let nonce_bytes = &raw_bytes[..NONCE_LEN];
        let hmac_bytes = &raw_bytes[NONCE_LEN..NONCE_LEN + HMAC_LEN];
        let ciphertext = &raw_bytes[NONCE_LEN + HMAC_LEN..];

        // Verify HMAC
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key)
            .map_err(|_| CryptoError::HmacMismatch)?;
        mac.update(nonce_bytes);
        mac.update(ciphertext);

        mac.verify_slice(hmac_bytes)
            .map_err(|_| CryptoError::HmacMismatch)?;

        // Decrypt ciphertext
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher =
            Aes256Gcm::new_from_slice(&self.aes_key).map_err(|_| CryptoError::DecryptionFailed)?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Get current unix timestamp in seconds
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Verify that timestamp is within acceptable window
    pub fn verify_timestamp(ts: u64, max_window_secs: Option<u64>) -> Result<(), CryptoError> {
        let current = Self::current_timestamp();
        let window = max_window_secs.unwrap_or(REPLAY_WINDOW_SECS);
        let diff = current.abs_diff(ts);

        if diff > window {
            Err(CryptoError::TimestampExpired)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_success() {
        let crypto = CryptoManager::new("secret_key_123");
        let payload = b"Hello UDP Knock";

        let encrypted = crypto.encrypt(payload).expect("Encryption failed");
        let decrypted = crypto.decrypt(&encrypted).expect("Decryption failed");

        assert_eq!(payload.to_vec(), decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let crypto = CryptoManager::new("secret_key_123");
        let payload = b"Sensitive Command";

        let encrypted = crypto.encrypt(payload).expect("Encryption failed");
        let mut raw = BASE64.decode(&encrypted).unwrap();
        // Tamper with the ciphertext byte
        let last_idx = raw.len() - 1;
        raw[last_idx] ^= 0xFF;
        let tampered = BASE64.encode(raw);

        assert_eq!(crypto.decrypt(&tampered), Err(CryptoError::HmacMismatch));
    }

    #[test]
    fn test_wrong_key_fails() {
        let crypto1 = CryptoManager::new("secret_key_123");
        let crypto2 = CryptoManager::new("wrong_key_456");

        let encrypted = crypto1.encrypt(b"Secret").unwrap();
        assert!(crypto2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_timestamp_verification() {
        let now = CryptoManager::current_timestamp();
        assert!(CryptoManager::verify_timestamp(now, None).is_ok());
        assert!(CryptoManager::verify_timestamp(now - 10, None).is_ok());
        assert!(CryptoManager::verify_timestamp(now - 31, None).is_err());
        assert!(CryptoManager::verify_timestamp(now + 31, None).is_err());
    }
}
