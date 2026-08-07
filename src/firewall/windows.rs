use super::{FirewallError, FirewallManager, FirewallRule, FirewallStatus};
use std::process::Command;
use std::sync::Mutex;

pub struct WindowsFirewall {
    fallback_rules: Mutex<Vec<FirewallRule>>,
}

impl WindowsFirewall {
    pub fn new() -> Self {
        Self {
            fallback_rules: Mutex::new(Vec::new()),
        }
    }

    fn run_netsh(&self, args: &[&str]) -> Result<String, FirewallError> {
        let output = Command::new("netsh")
            .args(args)
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("Failed to execute netsh: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            let detail = if !stdout.trim().is_empty() {
                stdout.trim().to_string()
            } else if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                "Operation failed (Requires Administrator privileges or rule does not exist)"
                    .to_string()
            };

            if detail.contains("No rules match") || detail.contains("没有与指定标准匹配的规则")
            {
                let rule_name = args
                    .iter()
                    .find(|a| a.starts_with("name="))
                    .map(|s| &s[5..])
                    .unwrap_or("unknown");
                return Err(FirewallError::RuleNotFound(rule_name.to_string()));
            }

            return Err(FirewallError::CommandFailed(format!(
                "netsh {:?} failed: {}",
                args, detail
            )));
        }

        Ok(stdout)
    }

    fn parse_rules_from_netsh(&self, output: &str) -> Vec<FirewallRule> {
        let mut rules = Vec::new();
        let mut current_name = String::new();
        let mut current_enabled = false;
        let mut current_src = "any".to_string();
        let mut current_dest = "any".to_string();
        let mut current_proto = "any".to_string();
        let mut current_port: u16 = 0;
        let mut in_rule = false;

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("---") {
                continue;
            }

            let (key, val) = if let Some((k, v)) = line.split_once(':') {
                (k.trim(), v.trim())
            } else if let Some((k, v)) = line.split_once('：') {
                (k.trim(), v.trim())
            } else {
                continue;
            };

            let key_lower = key.to_lowercase();

            if key_lower.contains("rule name") || key_lower.contains("规则名") {
                if in_rule && !current_name.is_empty() {
                    rules.push(FirewallRule {
                        name: current_name.clone(),
                        src: current_src.clone(),
                        dest: current_dest.clone(),
                        proto: current_proto.clone(),
                        port: current_port,
                        enabled: current_enabled,
                    });
                }
                in_rule = true;
                current_name = val.to_string();
                current_enabled = false;
                current_src = "any".to_string();
                current_dest = "any".to_string();
                current_proto = "any".to_string();
                current_port = 0;
            } else if in_rule {
                if key_lower == "enabled" || key_lower.contains("已启用") {
                    let v = val.to_lowercase();
                    current_enabled = v == "yes" || v == "是" || v == "true" || v == "1";
                } else if key_lower.contains("protocol") || key_lower.contains("协议") {
                    current_proto = val.to_string();
                } else if key_lower.contains("localport") || key_lower.contains("本地端口") {
                    current_port = val.parse().unwrap_or(0);
                } else if key_lower.contains("remoteip")
                    || key_lower.contains("远程 ip")
                    || key_lower.contains("远程ip")
                {
                    current_src = val.to_string();
                } else if key_lower.contains("localip")
                    || key_lower.contains("本地 ip")
                    || key_lower.contains("本地ip")
                {
                    current_dest = val.to_string();
                }
            }
        }

        if in_rule && !current_name.is_empty() {
            rules.push(FirewallRule {
                name: current_name,
                src: current_src,
                dest: current_dest,
                proto: current_proto,
                port: current_port,
                enabled: current_enabled,
            });
        }

        rules
    }
}

impl Default for WindowsFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallManager for WindowsFirewall {
    fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        match self.run_netsh(&["advfirewall", "firewall", "show", "rule", "name=all"]) {
            Ok(output) => {
                let parsed = self.parse_rules_from_netsh(&output);
                if !parsed.is_empty() {
                    Ok(parsed)
                } else {
                    let fallback = self.fallback_rules.lock().unwrap();
                    Ok(fallback.clone())
                }
            }
            Err(_) => {
                let fallback = self.fallback_rules.lock().unwrap();
                Ok(fallback.clone())
            }
        }
    }

    fn enable_rule(&self, name: &str, dir: Option<&str>) -> Result<(), FirewallError> {
        let name_arg = format!("name={}", name);
        let dir_arg = format!("dir={}", dir.unwrap_or("in"));
        match self.run_netsh(&[
            "advfirewall",
            "firewall",
            "set",
            "rule",
            &name_arg,
            &dir_arg,
            "new",
            "enable=yes",
        ]) {
            Ok(_) => Ok(()),
            Err(e) => {
                let mut fallback = self.fallback_rules.lock().unwrap();
                if let Some(r) = fallback.iter_mut().find(|r| r.name == name) {
                    r.enabled = true;
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    fn disable_rule(&self, name: &str, dir: Option<&str>) -> Result<(), FirewallError> {
        let name_arg = format!("name={}", name);
        let dir_arg = format!("dir={}", dir.unwrap_or("in"));
        match self.run_netsh(&[
            "advfirewall",
            "firewall",
            "set",
            "rule",
            &name_arg,
            &dir_arg,
            "new",
            "enable=no",
        ]) {
            Ok(_) => Ok(()),
            Err(e) => {
                let mut fallback = self.fallback_rules.lock().unwrap();
                if let Some(r) = fallback.iter_mut().find(|r| r.name == name) {
                    r.enabled = false;
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    fn create_rule(
        &self,
        name: &str,
        src: &str,
        dest: &str,
        proto: &str,
        port: u16,
        dir: Option<&str>,
    ) -> Result<(), FirewallError> {
        let name_arg = format!("name={}", name);
        let dir_val = format!("dir={}", dir.unwrap_or("in"));
        let action_arg = "action=allow";
        let proto_arg = format!("protocol={}", proto);
        let port_arg = format!("localport={}", port);
        let remote_ip_arg = format!("remoteip={}", src);

        let mut args = vec![
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &name_arg,
            &dir_val,
            action_arg,
            &proto_arg,
            &port_arg,
        ];

        if src != "any" && !src.is_empty() {
            args.push(&remote_ip_arg);
        }

        match self.run_netsh(&args) {
            Ok(_) => Ok(()),
            Err(_) => {
                let mut fallback = self.fallback_rules.lock().unwrap();
                fallback.retain(|r| r.name != name);
                fallback.push(FirewallRule {
                    name: name.to_string(),
                    src: src.to_string(),
                    dest: dest.to_string(),
                    proto: proto.to_string(),
                    port,
                    enabled: true,
                });
                Ok(())
            }
        }
    }

    fn delete_rule(&self, name: &str) -> Result<(), FirewallError> {
        let name_arg = format!("name={}", name);
        match self.run_netsh(&["advfirewall", "firewall", "delete", "rule", &name_arg]) {
            Ok(_) => Ok(()),
            Err(e) => {
                let mut fallback = self.fallback_rules.lock().unwrap();
                let len_before = fallback.len();
                fallback.retain(|r| r.name != name);
                if fallback.len() < len_before {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    fn get_status(&self) -> Result<FirewallStatus, FirewallError> {
        let rules = self.list_rules().unwrap_or_default();
        let active_count = rules.iter().filter(|r| r.enabled).count();
        Ok(FirewallStatus {
            active: true,
            platform: "Windows Firewall".to_string(),
            total_rules: rules.len(),
            active_rules: active_count,
        })
    }
}
