use async_trait::async_trait;
use serde_json::Value;
use tokio::process::Command;

use crate::error::AppError;
use super::FirewallManager;

pub struct OpenWrtFirewall;

impl OpenWrtFirewall {
    pub fn new() -> Self {
        Self
    }

    async fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, AppError> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .await
            .map_err(|e| AppError::Firewall(format!("Failed to execute {}: {}", cmd, e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Firewall(format!(
                "{} failed: {}", cmd, stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[async_trait]
impl FirewallManager for OpenWrtFirewall {
    async fn list_rules(&self) -> Result<Value, AppError> {
        let output = Self::run_cmd("uci", &["show", "firewall"]).await?;
        // Parse uci output into JSON (simplified)
        let rules: Vec<Value> = output
            .lines()
            .filter(|l| l.contains(".name="))
            .map(|l| {
                let parts: Vec<&str> = l.splitn(2, '=').collect();
                serde_json::json!({
                    "key": parts.first().unwrap_or(&""),
                    "name": parts.get(1).unwrap_or(&"").trim_matches('\'')
                })
            })
            .collect();
        Ok(Value::Array(rules))
    }

    async fn enable_rule(&self, name: &str) -> Result<(), AppError> {
        // Find rule index by name, then set enabled=1
        let show = Self::run_cmd("uci", &["show", "firewall"]).await?;
        let idx = find_rule_index(&show, name)?;
        Self::run_cmd("uci", &["set", &format!("firewall.@rule[{}].enabled=1", idx)]).await?;
        Self::run_cmd("uci", &["commit", "firewall"]).await?;
        Self::run_cmd("/etc/init.d/firewall", &["reload"]).await?;
        Ok(())
    }

    async fn disable_rule(&self, name: &str) -> Result<(), AppError> {
        let show = Self::run_cmd("uci", &["show", "firewall"]).await?;
        let idx = find_rule_index(&show, name)?;
        Self::run_cmd("uci", &["set", &format!("firewall.@rule[{}].enabled=0", idx)]).await?;
        Self::run_cmd("uci", &["commit", "firewall"]).await?;
        Self::run_cmd("/etc/init.d/firewall", &["reload"]).await?;
        Ok(())
    }

    async fn create_rule(&self, name: &str, src: &str, dest: &str, proto: &str, port: &str) -> Result<(), AppError> {
        Self::run_cmd("uci", &["add", "firewall", "rule"]).await?;
        Self::run_cmd("uci", &["set", &format!("firewall.@rule[-1].name={}", name)]).await?;
        Self::run_cmd("uci", &["set", &format!("firewall.@rule[-1].src={}", src)]).await?;
        Self::run_cmd("uci", &["set", &format!("firewall.@rule[-1].dest={}", dest)]).await?;
        Self::run_cmd("uci", &["set", &format!("firewall.@rule[-1].proto={}", proto)]).await?;
        Self::run_cmd("uci", &["set", &format!("firewall.@rule[-1].dest_port={}", port)]).await?;
        Self::run_cmd("uci", &["set", "firewall.@rule[-1].target=ACCEPT"]).await?;
        Self::run_cmd("uci", &["commit", "firewall"]).await?;
        Self::run_cmd("/etc/init.d/firewall", &["reload"]).await?;
        Ok(())
    }

    async fn delete_rule(&self, name: &str) -> Result<(), AppError> {
        let show = Self::run_cmd("uci", &["show", "firewall"]).await?;
        let idx = find_rule_index(&show, name)?;
        Self::run_cmd("uci", &["delete", &format!("firewall.@rule[{}]", idx)]).await?;
        Self::run_cmd("uci", &["commit", "firewall"]).await?;
        Self::run_cmd("/etc/init.d/firewall", &["reload"]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<Value, AppError> {
        let output = Self::run_cmd("/etc/init.d/firewall", &["status"]).await
            .or_else(|_| Self::run_cmd("fw4", &["print"])).await
            .unwrap_or_else(|_| "unknown".into());
        Ok(serde_json::json!({ "status": output.trim() }))
    }
}

fn find_rule_index(uci_output: &str, name: &str) -> Result<usize, AppError> {
    let target = format!(".name='{}'", name);
    for line in uci_output.lines() {
        if line.contains(&target) {
            // Extract index from firewall.@rule[N].name='...'
            if let Some(start) = line.find("@rule[") {
                let rest = &line[start + 6..];
                if let Some(end) = rest.find(']') {
                    let idx_str = &rest[..end];
                    return idx_str
                        .parse()
                        .map_err(|_| AppError::Firewall(format!("Cannot parse rule index for '{}'", name)));
                }
            }
        }
    }
    Err(AppError::Firewall(format!("Rule '{}' not found", name)))
}