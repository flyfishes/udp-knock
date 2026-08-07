use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::config::Config;
use crate::crypto::CryptoContext;
use crate::error::AppError;
use crate::protocol::{Request, Response};

pub struct Client {
    config: Config,
    crypto: CryptoContext,
}

impl Client {
    pub fn new(config: Config) -> Self {
        let crypto = CryptoContext::new(&config.shared_secret);
        Self { config, crypto }
    }

    pub async fn send(&self, request: Request) -> Result<Response, AppError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.config.listen_addr).await?;

        let json = serde_json::to_vec(&request)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let packet = self.crypto.seal(&json, ts)?;

        socket.send(&packet).await?;

        // Receive with timeout
        let mut buf = [0u8; 4096];
        let dur = Duration::from_secs(self.config.timeout_secs);
        let len = timeout(dur, socket.recv(&mut buf))
            .await
            .map_err(|_| AppError::Timeout)??;

        let (plaintext, _resp_ts) = self.crypto.open(&buf[..len])?;
        let response: Response = serde_json::from_slice(&plaintext)?;
        Ok(response)
    }
}