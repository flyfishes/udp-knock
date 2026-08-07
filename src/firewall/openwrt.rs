use super::{FirewallError, FirewallManager, FirewallRule, FirewallStatus};
use std::collections::HashMap;
use std::process::Command;

pub struct OpenWrtFirewall;

impl OpenWrtFirewall {
    pub fn new() -> Self {
        Self
    }

    fn run_cmd(&self, program: &str, args: &[&str]) -> Result<String, FirewallError> {
        let output = Command::new(program).args(args).output().map_err(|e| {
            FirewallError::CommandFailed(format!("Failed to execute {}: {}", program, e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "Command {} {:?} failed: {}",
                program, args, stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn reload_firewall(&self) -> Result<(), FirewallError> {
        // Run uci commit firewall
        let _ = self.run_cmd("uci", &["commit", "firewall"])?;
        // Run firewall reload or init script reload
        let res = self
            .run_cmd("fw4", &["reload"])
            .or_else(|_| self.run_cmd("fw3", &["reload"]))
            .or_else(|_| self.run_cmd("/etc/init.d/firewall", &["reload"]));

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                log::warn!("Firewall reload command fallback notice: {}", e);
                Ok(())
            }
        }
    }
}

impl Default for OpenWrtFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallManager for OpenWrtFirewall {
    fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        let output = match self.run_cmd("uci", &["show", "firewall"]) {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()), // If uci is not present/fails, return empty
        };

        // Key: rule section key (e.g. firewall.my_rule or firewall.@rule[0])
        // Value: HashMap of field -> value
        let mut rules_map: HashMap<String, HashMap<String, String>> = HashMap::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with("firewall.") {
                continue;
            }

            if let Some((key_part, val_part)) = line.split_once('=') {
                let parts: Vec<&str> = key_part.split('.').collect();
                if parts.len() >= 2 {
                    let section = parts[1].to_string();
                    let field = if parts.len() >= 3 { parts[2] } else { "" };
                    let clean_val = val_part.trim_matches('\'').trim_matches('"').to_string();

                    let entry = rules_map.entry(section).or_default();
                    if !field.is_empty() {
                        entry.insert(field.to_string(), clean_val);
                    } else {
                        entry.insert("_type".to_string(), clean_val);
                    }
                }
            }
        }

        let mut rules = Vec::new();
        for (section_name, fields) in rules_map {
            let rule_type = fields.get("_type").cloned().unwrap_or_default();
            if rule_type == "rule" || fields.contains_key("name") {
                let name = fields
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| section_name.clone());
                let src = fields
                    .get("src")
                    .cloned()
                    .unwrap_or_else(|| "any".to_string());
                let dest = fields
                    .get("dest")
                    .cloned()
                    .unwrap_or_else(|| "any".to_string());
                let proto = fields
                    .get("proto")
                    .cloned()
                    .unwrap_or_else(|| "all".to_string());
                let port: u16 = fields
                    .get("dest_port")
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                let enabled = fields.get("enabled").map(|e| e == "1").unwrap_or(true);

                rules.push(FirewallRule {
                    name,
                    src,
                    dest,
                    proto,
                    port,
                    enabled,
                });
            }
        }

        Ok(rules)
    }

    fn enable_rule(&self, name: &str) -> Result<(), FirewallError> {
        let set_arg = format!("firewall.{}.enabled=1", name);
        self.run_cmd("uci", &["set", &set_arg])?;
        self.reload_firewall()
    }

    fn disable_rule(&self, name: &str) -> Result<(), FirewallError> {
        let set_arg = format!("firewall.{}.enabled=0", name);
        self.run_cmd("uci", &["set", &set_arg])?;
        self.reload_firewall()
    }

    fn create_rule(
        &self,
        name: &str,
        src: &str,
        dest: &str,
        proto: &str,
        port: u16,
    ) -> Result<(), FirewallError> {
        let name_arg = format!("firewall.{}.name={}", name, name);
        let type_arg = format!("firewall.{}=rule", name);
        let src_arg = format!("firewall.{}.src={}", name, src);
        let dest_arg = format!("firewall.{}.dest={}", name, dest);
        let proto_arg = format!("firewall.{}.proto={}", name, proto);
        let port_arg = format!("firewall.{}.dest_port={}", name, port);
        let target_arg = format!("firewall.{}.target=ACCEPT", name);
        let enabled_arg = format!("firewall.{}.enabled=1", name);

        self.run_cmd("uci", &["set", &type_arg])?;
        self.run_cmd("uci", &["set", &name_arg])?;
        self.run_cmd("uci", &["set", &src_arg])?;
        self.run_cmd("uci", &["set", &dest_arg])?;
        self.run_cmd("uci", &["set", &proto_arg])?;
        self.run_cmd("uci", &["set", &port_arg])?;
        self.run_cmd("uci", &["set", &target_arg])?;
        self.run_cmd("uci", &["set", &enabled_arg])?;

        self.reload_firewall()
    }

    fn delete_rule(&self, name: &str) -> Result<(), FirewallError> {
        let delete_arg = format!("firewall.{}", name);
        self.run_cmd("uci", &["delete", &delete_arg])?;
        self.reload_firewall()
    }

    fn get_status(&self) -> Result<FirewallStatus, FirewallError> {
        let rules = self.list_rules().unwrap_or_default();
        let total_rules = rules.len();
        let active_rules = rules.iter().filter(|r| r.enabled).count();

        Ok(FirewallStatus {
            active: true,
            platform: "OpenWrt".to_string(),
            total_rules,
            active_rules,
        })
    }
}
