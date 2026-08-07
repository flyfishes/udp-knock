use serde::{Deserialize, Serialize};
use std::error::Error;

pub type FirewallResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub src: String,
    pub dest: String,
    pub proto: String,
    pub ports: String,
    pub enabled: bool,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub active: bool,
    pub rules_count: usize,
    pub default_policy: String,
    pub platform: String,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallResponse {
    pub success: bool,
    pub message: String,
    pub rules: Option<Vec<FirewallRule>>,
    pub status: Option<FirewallStatus>,
}

/// 防火墙管理器 trait
pub trait FirewallManager: Send + Sync {
    /// 获取防火墙状态
    fn get_status(&self) -> FirewallResult<FirewallStatus>;
    
    /// 列出所有规则
    fn list_rules(&self) -> FirewallResult<Vec<FirewallRule>>;
    
    /// 启用规则
    fn enable_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse>;
    
    /// 禁用规则
    fn disable_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse>;
    
    /// 创建规则
    fn create_rule(&self, rule: &FirewallRule) -> FirewallResult<FirewallResponse>;
    
    /// 删除规则
    fn delete_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse>;
    
    /// 更新规则
    fn update_rule(&self, rule: &FirewallRule) -> FirewallResult<FirewallResponse>;
    
    /// 检查规则是否存在
    fn rule_exists(&self, rule_name: &str) -> FirewallResult<bool>;
    
    /// 重新加载防火墙配置
    fn reload(&self) -> FirewallResult<()>;
}

/// 防火墙工厂
pub fn create_firewall_manager(config: &crate::config::Config) 
    -> FirewallResult<Box<dyn FirewallManager>> {
    
    let firewall_type = &config.server.firewall.firewall_type;
    let platform = &config.platform;
    
    #[cfg(feature = "firewall-openwrt")]
    if firewall_type == "openwrt" || (firewall_type == "auto" && platform == "openwrt") {
        return Ok(Box::new(super::openwrt::OpenWrtFirewall::new(config)?));
    }
    
    #[cfg(feature = "firewall-linux")]
    if firewall_type == "iptables" || (firewall_type == "auto" && platform == "linux") {
        return Ok(Box::new(super::linux::LinuxFirewall::new(config)?));
    }
    
    #[cfg(feature = "firewall-windows")]
    if firewall_type == "windows" || (firewall_type == "auto" && platform == "windows") {
        return Ok(Box::new(super::windows::WindowsFirewall::new(config)?));
    }
    
    Err(format!("不支持的防火墙类型: {} (平台: {})", firewall_type, platform).into())
}