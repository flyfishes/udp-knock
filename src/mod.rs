// src/client/mod.rs

mod command;

pub use command::Client;

use crate::config::Config;
use crate::crypto::Security;
use tokio::net::UdpSocket;

pub struct Client {
    config: Config,
    security: Security,
    socket: UdpSocket,
}

impl Client {
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let security = Security::new(
            &config.security.shared_key,
            config.security.timestamp_window,
            config.debug,
        );

        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            config,
            security,
            socket,
        })
    }

    pub async fn send_command(&self, action: &str, params: &[String]) -> Result<String, String> {
        command::send_command(
            &self.config,
            &self.security,
            &self.socket,
            action,
            params,
        ).await
    }
}