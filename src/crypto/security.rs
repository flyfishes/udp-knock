// src/crypto/security.rs

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const NONCE_SIZE: usize = 12;
const HMAC_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct Security {
    key: [u8; 32],
    timestamp_window: i64,
    debug: bool,
}

impl Security {
    pub fn new(shared_key: &str, timestamp_window: i64, debug: bool) -> Self {
        // 使用SHA256派生32字节密钥
        let mut hasher = sha2::Sha256::new();
        hasher.update(shared_key.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);

        Self {
            key,
            timestamp_window,
            debug,
        }
    }

    /// 加密消息（包含时间戳防止重放攻击）
    pub fn encrypt_message(&self, command: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        // 生成随机nonce
        let nonce_bytes = rand::random::<[u8; NONCE_SIZE]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 获取当前时间戳
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        // 构造明文: timestamp + command
        let mut plaintext = Vec::with_capacity(8 + command.len());
        plaintext.extend_from_slice(&timestamp.to_be_bytes());
        plaintext.extend_from_slice(command);

        // AES-GCM加密
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

        // 计算HMAC
        let mut mac = HmacSha256::new_from_slice(&self.key)?;
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        let hmac_result = mac.finalize().into_bytes();

        // 组合: nonce + ciphertext + hmac
        let mut packet = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + HMAC_SIZE);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&hmac_result);

        if self.debug {
            log::debug!("加密消息 - 时间戳: {}, 命令长度: {}", timestamp, command.len());
        }

        Ok(STANDARD.encode(&packet))
    }

    /// 解密并验证消息
    pub fn decrypt_message(
        &self,
        encrypted: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Base64解码
        let packet = STANDARD.decode(encrypted)?;

        if packet.len() < NONCE_SIZE + HMAC_SIZE {
            return Err("数据包太小".into());
        }

        // 分离nonce, ciphertext, hmac
        let nonce_bytes = &packet[..NONCE_SIZE];
        let hmac_start = packet.len() - HMAC_SIZE;
        let ciphertext = &packet[NONCE_SIZE..hmac_start];
        let received_hmac = &packet[hmac_start..];

        // 验证HMAC
        let mut mac = HmacSha256::new_from_slice(&self.key)?;
        mac.update(nonce_bytes);
        mac.update(ciphertext);

        if let Err(_) = mac.verify_slice(received_hmac) {
            if self.debug {
                log::warn!("HMAC验证失败 - 可能是密钥不匹配或数据被篡改");
            }
            return Err("HMAC验证失败".into());
        }

        // AES-GCM解密
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        let plaintext = cipher.decrypt(nonce, ciphertext)?;

        // 提取时间戳
        if plaintext.len() < 8 {
            return Err("明文格式错误".into());
        }

        let timestamp_bytes: [u8; 8] = plaintext[..8].try_into().unwrap();
        let timestamp = i64::from_be_bytes(timestamp_bytes);
        let command = &plaintext[8..];

        // 检查时间戳
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        let time_diff = (current_time - timestamp).abs();
        if time_diff > self.timestamp_window {
            if self.debug {
                log::warn!(
                    "时间戳验证失败 - 差异: {}秒 (窗口: {}秒)",
                    time_diff,
                    self.timestamp_window
                );
            }
            return Err("时间戳超出允许窗口".into());
        }

        if self.debug {
            log::debug!("成功解密消息 - 时间戳: {}, 命令长度: {}", timestamp, command.len());
        }

        Ok(command.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let security = Security::new("test_key", 30, true);
        let command = b"test_command param1 param2";

        let encrypted = security.encrypt_message(command).unwrap();
        let decrypted = security.decrypt_message(&encrypted).unwrap();

        assert_eq!(command.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_key() {
        let security1 = Security::new("key1", 30, true);
        let security2 = Security::new("key2", 30, true);
        let command = b"test";

        let encrypted = security1.encrypt_message(command).unwrap();
        let result = security2.decrypt_message(&encrypted);

        assert!(result.is_err());
    }
}