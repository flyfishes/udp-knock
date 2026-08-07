use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 12;
const HMAC_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 8;

/// Header size before ciphertext: HMAC(32) + Timestamp(8)
pub const HEADER_LEN: usize = HMAC_LEN + TIMESTAMP_LEN;

pub struct CryptoContext {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl CryptoContext {
    pub fn new(shared_secret: &str) -> Self {
        let enc_key = derive_key(shared_secret, b"encryption");
        let mac_key = derive_key(shared_secret, b"authentication");
        Self { enc_key, mac_key }
    }

    /// Encrypt + sign: returns [HMAC(32) || Timestamp(8) || Nonce(12) || Ciphertext+Tag]
    pub fn seal(&self, plaintext: &[u8], timestamp: u64) -> Result<Vec<u8>, AppError> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // AES-256-GCM encrypt
        let cipher = Aes256Gcm::new_from_slice(&self.enc_key)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)?;

        // Build payload: timestamp || nonce || ciphertext
        let ts_bytes = timestamp.to_be_bytes();
        let mut signed_data = Vec::with_capacity(TIMESTAMP_LEN + NONCE_LEN + ciphertext.len());
        signed_data.extend_from_slice(&ts_bytes);
        signed_data.extend_from_slice(&nonce_bytes);
        signed_data.extend_from_slice(&ciphertext);

        // HMAC over (timestamp || nonce || ciphertext)
        let mut mac = HmacSha256::new_from_slice(&self.mac_key)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        mac.update(&signed_data);
        let hmac_tag = mac.finalize().into_bytes();

        // Final packet: HMAC || timestamp || nonce || ciphertext
        let mut packet = Vec::with_capacity(HMAC_LEN + signed_data.len());
        packet.extend_from_slice(&hmac_tag);
        packet.extend_from_slice(&signed_data);

        Ok(packet)
    }

    /// Verify + decrypt. Returns (plaintext, timestamp) or error.
    pub fn open(&self, packet: &[u8]) -> Result<(Vec<u8>, u64), AppError> {
        if packet.len() < HEADER_LEN + NONCE_LEN + 16 {
            return Err(AppError::Crypto("Packet too short".into()));
        }

        let (hmac_received, rest) = packet.split_at(HMAC_LEN);
        let (ts_bytes, body) = rest.split_at(TIMESTAMP_LEN);

        // Verify HMAC first (constant-time via hmac crate)
        let mut mac = HmacSha256::new_from_slice(&self.mac_key)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        mac.update(rest); // rest = timestamp || nonce || ciphertext
        mac.verify_slice(hmac_received)
            .map_err(|_| AppError::Crypto("HMAC verification failed".into()))?;

        // Extract timestamp
        let timestamp = u64::from_be_bytes(
            ts_bytes.try_into().map_err(|_| AppError::Crypto("Bad timestamp".into()))?,
        );

        // Decrypt
        let (nonce_bytes, ciphertext) = body.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&self.enc_key)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| AppError::Crypto("AES-GCM decryption failed".into()))?;

        Ok((plaintext, timestamp))
    }
}

fn derive_key(secret: &str, label: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(label);
    hasher.finalize().into()
}