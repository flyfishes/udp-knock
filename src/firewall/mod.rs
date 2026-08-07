use async_trait::async_trait;
use serde_json::Value;

use crate::error::AppError;

#[cfg(feature = "openwrt")]
pub mod openwrt;

#[async_trait]
pub trait FirewallManager: Send + Sync {
    async fn list_rules(&self) -> Result<Value, AppError>;
    async fn enable_rule(&self, name: &str) -> Result<(), AppError>;
    async fn disable_rule(&self, name: &str) -> Result<(), AppError>;
    async fn create_rule(&self, name: &str, src: &str, dest: &str, proto: &str, port: &str) -> Result<(), AppError>;
    async fn delete_rule(&self, name: &str) -> Result<(), AppError>;
    async fn status(&self) -> Result<Value, AppError>;
}

pub fn create_firewall_manager(platform: &str) -> Result<Box<dyn FirewallManager>, AppError> {
    match platform {
        #[cfg(feature = "openwrt")]
        "openwrt" => Ok(Box::new(openwrt::OpenWrtFirewall::new())),

        #[cfg(not(feature = "openwrt"))]
        "openwrt" => Err(AppError::Firewall("OpenWrt support not compiled in".into())),

        _ => Err(AppError::Firewall(format!("Unsupported platform: {}", platform))),
    }
}