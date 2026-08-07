use crate::config::ClientConfig;
use crate::crypto::CryptoManager;
use crate::server::{CommandPayload, ResponsePayload};
use std::net::UdpSocket;
use std::time::Duration;

pub struct Client {
    config: ClientConfig,
    debug: bool,
}

impl Client {
    pub fn new(config: ClientConfig, debug: bool) -> Self {
        Self { config, debug }
    }

    pub fn send_command(
        &self,
        action: &str,
        params: &[String],
        override_timeout: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let crypto = CryptoManager::new(&self.config.shared_key);
        let payload = CommandPayload {
            action: action.to_string(),
            params: params.to_vec(),
            timestamp: CryptoManager::current_timestamp(),
        };

        let json_bytes = serde_json::to_vec(&payload)?;
        let encrypted_payload = crypto.encrypt(&json_bytes)?;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let timeout_secs = override_timeout.unwrap_or(self.config.timeout);
        socket.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;

        if self.debug {
            println!(
                "[DEBUG] Sending command '{}' to {}",
                action, self.config.server_addr
            );
        }

        socket.send_to(encrypted_payload.as_bytes(), &self.config.server_addr)?;

        let mut buf = [0u8; 4096];
        let (amt, _) = socket.recv_from(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                format!("Request timed out after {} seconds (Server may be unreachable or credentials mismatch)", timeout_secs)
            } else {
                format!("Failed to receive response: {}", e)
            }
        })?;

        let resp_raw = std::str::from_utf8(&buf[..amt])?.trim();
        let decrypted_bytes = crypto
            .decrypt(resp_raw)
            .map_err(|e| format!("Failed to decrypt server response: {}", e))?;

        let resp: ResponsePayload = serde_json::from_slice(&decrypted_bytes)?;

        if resp.success {
            println!("✅ Success: {}", resp.message);
            if let Some(data) = resp.data {
                println!("{}", serde_json::to_string_pretty(&data)?);
            }
        } else {
            eprintln!("❌ Error: {}", resp.message);
        }

        Ok(())
    }
}
