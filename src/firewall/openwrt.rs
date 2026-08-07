#![cfg(target_os = "openwrt")]
use super::traits::*;
use crate::config::Config;
use log::{debug, error};
use std::process::Command;
use std::str;

pub struct OpenWrtFirewall {
    config: Config,
    debug: bool,
}

impl OpenWrtFirewall {
    pub fn new(config: &Config) -> FirewallResult<Self> {
        // 检查uci命令是否存在
        let check = Command::new("which").arg("uci").output();
        if check.is_err() || !check.unwrap().status.success() {
            return Err("uci命令未找到，可能不是OpenWrt系统".into());
        }
        
        Ok(Self {
            config: config.clone(),
            debug: config.debug,
        })
    }

    fn exec_uci(&self, args: &[&str]) -> Result<String, String> {
        if self.debug {
            debug!("执行命令: uci {}", args.join(" "));
        }
        
        let output = Command::new("uci")
            .args(args)
            .output()
            .map_err(|e| format!("执行uci命令失败: {}", e))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("uci命令失败: {}", stderr));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim().to_string())
    }

    fn exec_firewall_reload(&self) -> Result<(), String> {
        if self.debug {
            debug("重新加载防火墙配置...");
        }
        
        // OpenWrt防火墙重载
        self.exec_uci(&["commit", "firewall"])?;
        
        let output = Command::new("sh")
            .arg("-c")
            .arg("/etc/init.d/firewall reload")
            .output()
            .map_err(|e| format!("重载防火墙失败: {}", e))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("重载防火墙失败: {}", stderr));
        }
        
        Ok(())
    }
}

impl FirewallManager for OpenWrtFirewall {
    fn get_status(&self) -> FirewallResult<FirewallStatus> {
        let output = self.exec_uci(&["show", "firewall"])
            .map_err(|e| format!("获取防火墙状态失败: {}", e))?;
        
        // 解析输出
        let rules_count = output.lines()
            .filter(|line| line.contains(".redirect"))
            .count();
        
        Ok(FirewallStatus {
            active: true,
            rules_count,
            default_policy: "ACCEPT".to_string(),
            platform: "OpenWrt".to_string(),
            zones: vec!["lan".to_string(), "wan".to_string()],
        })
    }

    fn list_rules(&self) -> FirewallResult<Vec<FirewallRule>> {
        let output = self.exec_uci(&["show", "firewall"])
            .map_err(|e| format!("列出规则失败: {}", e))?;
        
        let mut rules = Vec::new();
        let mut current_rule: Option<FirewallRule> = None;
        
        for line in output.lines() {
            if line.contains(".redirect=") {
                if let Some(rule) = current_rule.take() {
                    rules.push(rule);
                }
                
                // 提取规则名
                if let Some(name) = line.split('.').nth(1) {
                    if let Some(name) = name.split('=').next() {
                        current_rule = Some(FirewallRule {
                            name: name.to_string(),
                            src: String::new(),
                            dest: String::new(),
                            proto: String::new(),
                            ports: String::new(),
                            enabled: true,
                            target: String::new(),
                            description: String::new(),
                        });
                    }
                }
            } else if let Some(rule) = &mut current_rule {
                // 解析规则属性
                if line.contains(".src=") {
                    if let Some(src) = line.split('=').last() {
                        rule.src = src.to_string();
                    }
                } else if line.contains(".dest=") {
                    if let Some(dest) = line.split('=').last() {
                        rule.dest = dest.to_string();
                    }
                } else if line.contains(".proto=") {
                    if let Some(proto) = line.split('=').last() {
                        rule.proto = proto.to_string();
                    }
                } else if line.contains(".dest_port=") {
                    if let Some(ports) = line.split('=').last() {
                        rule.ports = ports.to_string();
                    }
                } else if line.contains(".enabled=") {
                    if let Some(enabled) = line.split('=').last() {
                        rule.enabled = enabled == "1";
                    }
                }
            }
        }
        
        if let Some(rule) = current_rule.take() {
            rules.push(rule);
        }
        
        Ok(rules)
    }

    fn enable_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse> {
        // 检查规则是否存在
        match self.exec_uci(&["get", &format!("firewall.{}", rule_name)]) {
            Ok(_) => {},
            Err(_) => {
                return Ok(FirewallResponse {
                    success: false,
                    message: format!("规则 {} 不存在", rule_name),
                    rules: None,
                    status: None,
                });
            }
        }
        
        // 启用规则
        self.exec_uci(&["set", &format!("firewall.{}.enabled", rule_name), "1"])
            .map_err(|e| format!("启用规则失败: {}", e))?;
        
        // 提交并重载
        self.exec_firewall_reload()
            .map_err(|e| format!("重载防火墙失败: {}", e))?;
        
        Ok(FirewallResponse {
            success: true,
            message: format!("规则 {} 已启用", rule_name),
            rules: None,
            status: None,
        })
    }

    fn disable_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse> {
        match self.exec_uci(&["get", &format!("firewall.{}", rule_name)]) {
            Ok(_) => {},
            Err(_) => {
                return Ok(FirewallResponse {
                    success: false,
                    message: format!("规则 {} 不存在", rule_name),
                    rules: None,
                    status: None,
                });
            }
        }
        
        self.exec_uci(&["set", &format!("firewall.{}.enabled", rule_name), "0"])
            .map_err(|e| format!("禁用规则失败: {}", e))?;
        
        self.exec_firewall_reload()
            .map_err(|e| format!("重载防火墙失败: {}", e))?;
        
        Ok(FirewallResponse {
            success: true,
            message: format!("规则 {} 已禁用", rule_name),
            rules: None,
            status: None,
        })
    }

    fn create_rule(&self, rule: &FirewallRule) -> FirewallResult<FirewallResponse> {
        // 检查是否已存在
        if self.rule_exists(&rule.name)? {
            return Ok(FirewallResponse {
                success: false,
                message: format!("规则 {} 已存在", rule.name),
                rules: None,
                status: None,
            });
        }
        
        // 创建规则
        self.exec_uci(&["set", &format!("firewall.{}", rule.name), "redirect"])?;
        self.exec_uci(&["set", &format!("firewall.{}.src", rule.name), &rule.src])?;
        self.exec_uci(&["set", &format!("firewall.{}.dest", rule.name), &rule.dest])?;
        self.exec_uci(&["set", &format!("firewall.{}.proto", rule.name), &rule.proto])?;
        self.exec_uci(&["set", &format!("firewall.{}.dest_port", rule.name), &rule.ports])?;
        self.exec_uci(&["set", &format!("firewall.{}.target", rule.name), "ACCEPT"])?;
        self.exec_uci(&["set", &format!("firewall.{}.enabled", rule.name), 
            if rule.enabled { "1" } else { "0" }])?;
        
        if !rule.description.is_empty() {
            self.exec_uci(&["set", &format!("firewall.{}.description", rule.name), &rule.description])?;
        }
        
        self.exec_firewall_reload()?;
        
        Ok(FirewallResponse {
            success: true,
            message: format!("规则 {} 创建成功", rule.name),
            rules: None,
            status: None,
        })
    }

    fn delete_rule(&self, rule_name: &str) -> FirewallResult<FirewallResponse> {
        if !self.rule_exists(rule_name)? {
            return Ok(FirewallResponse {
                success: false,
                message: format!("规则 {} 不存在", rule_name),
                rules: None,
                status: None,
            });
        }
        
        self.exec_uci(&["delete", &format!("firewall.{}", rule_name)])?;
        self.exec_firewall_reload()?;
        
        Ok(FirewallResponse {
            success: true,
            message: format!("规则 {} 已删除", rule_name),
            rules: None,
            status: None,
        })
    }

    fn update_rule(&self, rule: &FirewallRule) -> FirewallResult<FirewallResponse> {
        if !self.rule_exists(&rule.name)? {
            return Ok(FirewallResponse {
                success: false,
                message: format!("规则 {} 不存在", rule.name),
                rules: None,
                status: None,
            });
        }
        
        // 先删除再创建（简化版本）
        self.delete_rule(&rule.name)?;
        self.create_rule(rule)?;
        
        Ok(FirewallResponse {
            success: true,
            message: format!("规则 {} 已更新", rule.name),
            rules: None,
            status: None,
        })
    }

    fn rule_exists(&self, rule_name: &str) -> FirewallResult<bool> {
        match self.exec_uci(&["get", &format!("firewall.{}", rule_name)]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn reload(&self) -> FirewallResult<()> {
        self.exec_firewall_reload()
            .map_err(|e| format!("重载防火墙失败: {}", e).into())
    }
}