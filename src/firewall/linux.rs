use super::{FirewallError, FirewallManager, FirewallRule, FirewallStatus};
use std::sync::Mutex;

pub struct LinuxFirewall {
    rules: Mutex<Vec<FirewallRule>>,
}

impl LinuxFirewall {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
        }
    }
}

impl Default for LinuxFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallManager for LinuxFirewall {
    fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        let rules = self.rules.lock().unwrap();
        Ok(rules.clone())
    }

    fn enable_rule(&self, name: &str, _dir: Option<&str>) -> Result<(), FirewallError> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(rule) = rules.iter_mut().find(|r| r.name == name) {
            rule.enabled = true;
            Ok(())
        } else {
            Err(FirewallError::RuleNotFound(name.to_string()))
        }
    }

    fn disable_rule(&self, name: &str, _dir: Option<&str>) -> Result<(), FirewallError> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(rule) = rules.iter_mut().find(|r| r.name == name) {
            rule.enabled = false;
            Ok(())
        } else {
            Err(FirewallError::RuleNotFound(name.to_string()))
        }
    }

    fn create_rule(
        &self,
        name: &str,
        src: &str,
        dest: &str,
        proto: &str,
        port: u16,
        _dir: Option<&str>,
    ) -> Result<(), FirewallError> {
        let mut rules = self.rules.lock().unwrap();
        rules.retain(|r| r.name != name);
        rules.push(FirewallRule {
            name: name.to_string(),
            src: src.to_string(),
            dest: dest.to_string(),
            proto: proto.to_string(),
            port,
            enabled: true,
        });
        Ok(())
    }

    fn delete_rule(&self, name: &str) -> Result<(), FirewallError> {
        let mut rules = self.rules.lock().unwrap();
        let len_before = rules.len();
        rules.retain(|r| r.name != name);
        if rules.len() < len_before {
            Ok(())
        } else {
            Err(FirewallError::RuleNotFound(name.to_string()))
        }
    }

    fn get_status(&self) -> Result<FirewallStatus, FirewallError> {
        let rules = self.rules.lock().unwrap();
        let active_count = rules.iter().filter(|r| r.enabled).count();
        Ok(FirewallStatus {
            active: true,
            platform: "Linux (Placeholder)".to_string(),
            total_rules: rules.len(),
            active_rules: active_count,
        })
    }
}
