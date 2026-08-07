use serde::Deserialize;
use std::path::Path;

use crate::error::AppError;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub shared_secret: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rpm: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_time_window")]
    pub time_window_secs: u64,
    #[serde(default = "default_platform")]
    pub platform: String,
}

fn default_rate_limit() -> u64 { 60 }
fn default_timeout() -> u64 { 5 }
fn default_time_window() -> u64 { 30 }
fn default_platform() -> String { "openwrt".into() }

impl Config {
    pub fn load(path: &str) -> Result<Self, AppError> {
        if !Path::new(path).exists() {
            return Err(AppError::Config(format!("Config file not found: {}", path)));
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| AppError::Config(e.to_string()))?;
        let config: Config = serde_json::from_str(&content)
            .map_err(|e| AppError::Config(e.to_string()))?;
        Ok(config)
    }

    pub fn generate_default(platform: &str) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "listen_addr": "0.0.0.0:9999",
            "shared_secret": "CHANGE_ME_TO_A_SECURE_RANDOM_STRING",
            "allowed_ips": [],
            "rate_limit_rpm": 60,
            "timeout_secs": 5,
            "time_window_secs": 30,
            "platform": platform
        })).unwrap()
    }
}