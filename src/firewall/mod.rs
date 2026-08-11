#![allow(dead_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub src: String,
    pub dest: String,
    pub proto: String,
    pub port: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub active: bool,
    pub platform: String,
    pub total_rules: usize,
    pub active_rules: usize,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum FirewallError {
    RuleNotFound(String),
    CommandFailed(String),
    NotImplemented(String),
    InvalidParameter(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::RuleNotFound(s) => write!(f, "Rule not found: {}", s),
            FirewallError::CommandFailed(s) => write!(f, "Firewall command failed: {}", s),
            FirewallError::NotImplemented(s) => write!(f, "Feature not implemented: {}", s),
            FirewallError::InvalidParameter(s) => write!(f, "Invalid parameter: {}", s),
        }
    }
}

impl std::error::Error for FirewallError {}

/// 防火墙更新配置
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FirewallUpdateConfig {
    pub name: String,
    pub direction: Option<String>,
    pub old_ip_pattern: String,
    pub new_ip: String,
    pub action: Option<String>,
    pub protocol: Option<String>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub local_addr: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

#[allow(unused_variables)]
pub trait FirewallManager: Send + Sync {
    fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError>;
    fn enable_rule(&self, name: &str, dir: Option<&str>) -> Result<(), FirewallError>;
    fn disable_rule(&self, name: &str, dir: Option<&str>) -> Result<(), FirewallError>;
    fn create_rule(
        &self,
        name: &str,
        src: &str,
        dest: &str,
        proto: &str,
        port: u16,
        dir: Option<&str>,
    ) -> Result<(), FirewallError>;
    fn delete_rule(&self, name: &str) -> Result<(), FirewallError>;
    fn get_status(&self) -> Result<FirewallStatus, FirewallError>;
    /// 默认实现返回不支持错误，各平台可选择性覆盖
	#[allow(clippy::too_many_arguments)]
    fn update_rule(
        &self,
        name: &str,
        direction: Option<&str>,
        old_ip_pattern: &str,
        new_ip: &str,
        action: Option<&str>,
        protocol: Option<&str>,
        local_port: Option<u16>,
        remote_port: Option<u16>,
        local_addr: Option<&str>,
        description: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<bool, FirewallError> {
        // 默认返回不支持
        Err(FirewallError::NotImplemented(
            "update_rule not supported on this platform".to_string()
        ))
    }

    /// 验证规则配置
    /// 默认实现返回不支持错误，各平台可选择性覆盖
    fn verify_rule(
        &self,
        name: &str,
        direction: Option<&str>,
        expected_ips: &[String],
        strict_mode: bool,
    ) -> Result<bool, FirewallError> {
        Err(FirewallError::NotImplemented(
            "verify_rule not supported on this platform".to_string()
        ))
    }
}

pub mod linux;
pub mod openwrt;
pub mod windows;

pub fn get_firewall_manager(platform: &str) -> Box<dyn FirewallManager> {
    match platform.to_lowercase().as_str() {
        "openwrt" => Box::new(openwrt::OpenWrtFirewall::new()),
        "linux" => Box::new(linux::LinuxFirewall::new()),
        "windows" => Box::new(windows::WindowsFirewall::new()),
        _ => Box::new(openwrt::OpenWrtFirewall::new()),
    }
}
