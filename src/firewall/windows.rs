// src/firewall/windows.rs
#![cfg(target_os = "windows")]

use super::traits::*;
use log::warn;

pub struct WindowsFirewall {
    debug: bool,
}

impl WindowsFirewall {
    pub fn new(config: &crate::config::Config) -> FirewallResult<Self> {
        warn!("Windows 防火墙功能尚未实现，使用占位实现");
        Ok(Self {
            debug: config.debug,
        })
    }
}

impl FirewallManager for WindowsFirewall {
    fn get_status(&self) -> FirewallResult<FirewallStatus> {
        Ok(FirewallStatus {
            active: true,
            rules_count: 0,
            default_policy: "Block".to_string(),
            platform: "Windows (stub)".to_string(),
            zones: vec!["Public".to_string(), "Private".to_string()],
        })
    }

    fn list_rules(&self) -> FirewallResult<Vec<FirewallRule>> {
        warn!("Windows list_rules: 功能尚未实现");
        Ok(vec![])
    }

    fn enable_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse> {
        warn!("Windows enable_rule: 功能尚未实现");
        Ok(FirewallResponse {
            success: false,
            message: format!("Windows: 规则 {} 启用功能尚未实现", rule_name),
            rules: None,
            status: None,
        })
    }

    fn disable_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse> {
        warn!("Windows disable_rule: 功能尚未实现");
        Ok(FirewallResponse {
            success: false,
            message: format!("Windows: 规则 {} 禁用功能尚未实现", rule_name),
            rules: None,
            status: None,
        })
    }

    fn create_rule(&self, rule: &FirewallRule) -> FirewallResult<FirewallResponse> {
        warn!("Windows create_rule: 功能尚未实现");
        Ok(FirewallResponse {
            success: false,
            message: format!("Windows: 规则 {} 创建功能尚未实现", rule.name),
            rules: None,
            status: None,
        })
    }

    fn delete_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse> {
        warn!("Windows delete_rule: 功能尚未实现");
        Ok(FirewallResponse {
            success: false,
            message: format!("Windows: 规则 {} 删除功能尚未实现", rule_name),
            rules: None,
            status: None,
        })
    }

    fn update_rule(&self, rule: &FirewallRule) -> FirewallResult<FirewallResponse> {
        warn!("Windows update_rule: 功能尚未实现");
        Ok(FirewallResponse {
            success: false,
            message: format!("Windows: 规则 {} 更新功能尚未实现", rule.name),
            rules: None,
            status: None,
        })
    }

    fn rule_exists(&self, rule_name: &str) -> FirewallResult<bool> {
        warn!("Windows rule_exists: 功能尚未实现");
        Ok(false)
    }

    fn reload(&self) -> FirewallResult<()> {
        warn!("Windows reload: 功能尚未实现");
        Ok(())
    }
}