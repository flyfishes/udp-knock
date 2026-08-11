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

            if detail.contains("No rules match") || detail.contains("没有与指定标准匹配的规则") {
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

    /// 获取规则当前的RemoteIP配置
    fn get_rule_remote_ips(&self, name: &str, direction: &str) -> Result<Vec<String>, FirewallError> {
        let output = self.run_netsh(&[
            "advfirewall", "firewall", "show", "rule",
            &format!("name={}", name),
            &format!("dir={}", direction),
        ])?;

        let mut ips = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
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
            if key_lower.contains("remoteip") || key_lower.contains("远程 ip") || key_lower.contains("远程ip") {
                // 可能包含多个IP，用逗号分隔
                for ip in val.split(',') {
                    let clean_ip = ip.trim();
                    if !clean_ip.is_empty() && clean_ip != "*" && clean_ip != "any" {
                        ips.push(clean_ip.to_string());
                    }
                }
                break;
            }
        }

        Ok(ips)
    }

    /// 获取规则详情
    fn get_rule_details(&self, name: &str, direction: &str) -> Result<FirewallRule, FirewallError> {
        let output = self.run_netsh(&[
            "advfirewall", "firewall", "show", "rule",
            &format!("name={}", name),
            &format!("dir={}", direction),
        ])?;

        let mut rule = FirewallRule {
            name: name.to_string(),
            src: "any".to_string(),
            dest: "any".to_string(),
            proto: "any".to_string(),
            port: 0,
            enabled: false,
        };

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
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

            if key_lower.contains("enabled") || key_lower.contains("已启用") {
                let v = val.to_lowercase();
                rule.enabled = v == "yes" || v == "是" || v == "true" || v == "1";
            } else if key_lower.contains("protocol") || key_lower.contains("协议") {
                rule.proto = val.to_string();
            } else if key_lower.contains("localport") || key_lower.contains("本地端口") {
                rule.port = val.parse().unwrap_or(0);
            } else if key_lower.contains("remoteip") || key_lower.contains("远程 ip") || key_lower.contains("远程ip") {
                rule.src = val.to_string();
            } else if key_lower.contains("localip") || key_lower.contains("本地 ip") || key_lower.contains("本地ip") {
                rule.dest = val.to_string();
            }
        }

        Ok(rule)
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

    // ========== IP匹配辅助函数 ==========

    /// 将IP地址转换为u32
    fn ip_to_u32(&self, parts: &[u8]) -> u32 {
        if parts.len() != 4 {
            return 0;
        }
        ((parts[0] as u32) << 24)
            | ((parts[1] as u32) << 16)
            | ((parts[2] as u32) << 8)
            | (parts[3] as u32)
    }

    /// 将IP字符串转换为u32
    fn ip_str_to_u32(&self, ip: &str) -> Option<u32> {
        let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
        if parts.len() == 4 {
            Some(self.ip_to_u32(&parts))
        } else {
            None
        }
    }

    /// CIDR匹配
    fn cidr_match(&self, cidr: &str, ip: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network = parts[0];
        let mask_bits: u8 = match parts[1].parse() {
            Ok(m) => m,
            Err(_) => return false,
        };

        if mask_bits > 32 {
            return false;
        }

        let network_int = match self.ip_str_to_u32(network) {
            Some(n) => n,
            None => return false,
        };

        let ip_int = match self.ip_str_to_u32(ip) {
            Some(n) => n,
            None => return false,
        };

        // 计算掩码
        let mask = if mask_bits == 0 {
            0
        } else {
            !((1u32 << (32 - mask_bits)) - 1)
        };

        (network_int & mask) == (ip_int & mask)
    }

    /// IP范围匹配 (如 192.168.0.1-192.168.0.254)
    fn range_match(&self, range: &str, ip: &str) -> bool {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return false;
        }

        let start_ip = parts[0].trim();
        let end_ip = parts[1].trim();

        let ip_int = match self.ip_str_to_u32(ip) {
            Some(n) => n,
            None => return false,
        };

        let start_int = match self.ip_str_to_u32(start_ip) {
            Some(n) => n,
            None => return false,
        };

        let end_int = match self.ip_str_to_u32(end_ip) {
            Some(n) => n,
            None => return false,
        };

        ip_int >= start_int && ip_int <= end_int
    }

    /// 通配符匹配 (如 192.168.*.*)
    fn wildcard_match(&self, pattern: &str, ip: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('.').collect();
        let ip_parts: Vec<&str> = ip.split('.').collect();

        if pattern_parts.len() != 4 || ip_parts.len() != 4 {
            return false;
        }

        for (p, i) in pattern_parts.iter().zip(ip_parts.iter()) {
            if *p != "*" && p != i {
                return false;
            }
        }
        true
    }

    /// IP匹配逻辑（支持多种格式）
    fn ip_match(&self, expected: &str, current: &str) -> bool {
        // 完全匹配
        if expected == current {
            return true;
        }

        // 处理 CIDR 格式 (如 192.168.0.0/24)
        if expected.contains('/') {
            return self.cidr_match(expected, current);
        }

        // 处理 IP 范围格式 (如 192.168.0.1-192.168.0.254)
        if expected.contains('-') {
            return self.range_match(expected, current);
        }

        // 处理通配符格式 (如 192.168.*.*)
        if expected.contains('*') {
            return self.wildcard_match(expected, current);
        }

        // 处理多IP格式 (如 192.168.0.1,192.168.0.2)
        if expected.contains(',') {
            return expected.split(',').any(|ip| self.ip_match(ip.trim(), current));
        }

        false
    }

    /// 检查单个期望IP是否匹配当前IP列表中的任何一个
    fn is_ip_matched(&self, expected: &str, current_ips: &[String]) -> bool {
        // 如果期望IP是 "any" 或 "*"，表示匹配所有
        if expected == "any" || expected == "*" {
            return !current_ips.is_empty();
        }

        // 检查当前IP列表中是否有匹配的
        current_ips.iter().any(|current| self.ip_match(expected, current))
    }

    /// 检查IP是否在IP列表中（支持多种格式）
    fn is_ip_in_list(&self, ip: &str, ip_list: &[String]) -> bool {
        ip_list.iter().any(|item| self.ip_match(item, ip))
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

// ========== 新增的 update_rule 相关功能 ==========

impl WindowsFirewall {
    /// 创建带完整参数的规则（内部辅助函数）
    fn create_rule_with_params(
        &self,
        name: &str,
        direction: &str,
        remote_ip: &str,
        action: &str,
        protocol: &str,
        local_port: Option<u16>,
        remote_port: Option<u16>,
        local_addr: Option<&str>,
        description: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<(), FirewallError> {
        let mut args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}", name),
            format!("dir={}", direction),
            format!("action={}", action),
            format!("protocol={}", protocol),
        ];

        if remote_ip != "any" && !remote_ip.is_empty() {
            args.push(format!("remoteip={}", remote_ip));
        }

        if let Some(port) = local_port {
            args.push(format!("localport={}", port));
        }

        if let Some(port) = remote_port {
            args.push(format!("remoteport={}", port));
        }

        if let Some(addr) = local_addr {
            if !addr.is_empty() {
                args.push(format!("localaddr={}", addr));
            }
        }

        if let Some(desc) = description {
            if !desc.is_empty() {
                args.push(format!("description={}", desc));
            }
        }

        if let Some(enabled) = enabled {
            args.push(format!("enabled={}", if enabled { "yes" } else { "no" }));
        }

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match self.run_netsh(&args_ref) {
            Ok(_) => Ok(()),
            Err(e) => {
                // 如果命令失败，保存到备用规则
                let mut fallback = self.fallback_rules.lock().unwrap();
                fallback.retain(|r| r.name != name);
                fallback.push(FirewallRule {
                    name: name.to_string(),
                    src: remote_ip.to_string(),
                    dest: local_addr.unwrap_or("any").to_string(),
                    proto: protocol.to_string(),
                    port: local_port.unwrap_or(0),
                    enabled: enabled.unwrap_or(true),
                });
                Err(e)
            }
        }
    }

    /// 更新防火墙规则的RemoteIP（核心函数）
    ///
    /// # 参数
    /// - `name`: 规则名称
    /// - `direction`: 方向 ("in" 或 "out")，默认 "in"
    /// - `old_ip_pattern`: 旧IP匹配模式（用于判断是否需要更新）
    /// - `new_ip`: 新的IP地址（可以是单个IP或多个IP用逗号分隔）
    /// - `action`: 动作 ("allow" 或 "block")，默认 "allow"
    /// - `protocol`: 协议 ("any", "tcp", "udp", "icmp")，默认 "any"
    /// - `local_port`: 本地端口（可选）
    /// - `remote_port`: 远程端口（可选）
    /// - `local_addr`: 本地地址（可选）
    /// - `description`: 规则描述（可选）
    /// - `enabled`: 是否启用（可选）
    ///
    /// # 返回值
    /// - `Ok(true)`: 规则已更新
    /// - `Ok(false)`: 规则已存在且配置正确，无需更新
    /// - `Err(FirewallError)`: 操作失败
    pub fn update_rule(
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
        let direction = direction.unwrap_or("in");
        let action = action.unwrap_or("allow");
        let protocol = protocol.unwrap_or("any");

        // 验证参数
        if name.is_empty() {
            return Err(FirewallError::InvalidParameter("规则名称不能为空".to_string()));
        }
        if new_ip.is_empty() {
            return Err(FirewallError::InvalidParameter("IP地址不能为空".to_string()));
        }

		log::debug!("try update_rule: {} {} NEWIP:{} OLD: {}", name, direction, new_ip, old_ip_pattern);        
        // 1. 检查规则是否存在
        match self.get_rule_details(name, direction) {
            Ok(_) => {
                log::debug!("  found rule: '{}'", name);
            }
            Err(FirewallError::RuleNotFound(_)) => {
                log::warn!(" rule '{}' not exists, create...", name);
                return self
                    .create_rule_with_params(
                        name,
                        direction,
                        new_ip,
                        action,
                        protocol,
                        local_port,
                        remote_port,
                        local_addr,
                        description,
                        enabled,
                    )
                    .map(|_| true);
            }
            Err(e) => return Err(e),
        }

        // 2. 获取当前RemoteIP配置
        let current_ips = self.get_rule_remote_ips(name, direction)?;
        log::debug!("  current RemoteIP: {:?}", current_ips);

        // 3. 判断是否需要更新
        let has_new_ip = self.is_ip_in_list(new_ip, &current_ips);
        let has_old_ip = current_ips.iter().any(|ip| ip.starts_with(old_ip_pattern));

        if has_new_ip && !has_old_ip {
            log::info!(" rule is same, not need update.");
            return Ok(false);
        }

        // 4. 需要更新：删除旧规则并创建新规则
        if has_new_ip && has_old_ip {
            log::debug!(" not same ip, will delete and recreate");
        } else {
            log::debug!(" old ip not matched, update it");
        }

        // 删除旧规则
        self.delete_rule(name)?;

        // 创建新规则
        self.create_rule_with_params(
            name,
            direction,
            new_ip,
            action,
            protocol,
            local_port,
            remote_port,
            local_addr,
            description,
            enabled,
        )?;

        log::info!(" rule: {} updated OK，RemoteIP: {}", name, new_ip);
        Ok(true)
    }

    /// 批量更新多个IP（便捷函数）
    pub fn update_rule_with_multiple_ips(
        &self,
        name: &str,
        direction: Option<&str>,
        old_ip_pattern: &str,
        new_ips: &[String],
        action: Option<&str>,
        protocol: Option<&str>,
        local_port: Option<u16>,
        remote_port: Option<u16>,
        local_addr: Option<&str>,
        description: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<bool, FirewallError> {
        if new_ips.is_empty() {
            return Err(FirewallError::InvalidParameter("IP列表不能为空".to_string()));
        }

        let direction = direction.unwrap_or("in");
        let ip_list = new_ips.join(",");

        self.update_rule(
            name,
            Some(direction),
            old_ip_pattern,
            &ip_list,
            action,
            protocol,
            local_port,
            remote_port,
            local_addr,
            description,
            enabled,
        )
    }

    /// 只更新IP，保留其他所有配置（便捷函数）
    pub fn update_rule_ip_only(
        &self,
        name: &str,
        direction: Option<&str>,
        old_ip_pattern: &str,
        new_ip: &str,
    ) -> Result<bool, FirewallError> {
        let direction = direction.unwrap_or("in");

        // 获取当前规则的完整配置
        let current_rule = self.get_rule_details(name, direction)?;

        // 使用当前配置，只更新IP
        self.update_rule(
            name,
            Some(direction),
            old_ip_pattern,
            new_ip,
            Some(&current_rule.proto),
            None,
            Some(current_rule.port),
            None,
            Some(&current_rule.dest),
            None,
            Some(current_rule.enabled),
        )
    }

    /// 验证规则是否存在且配置正确（增强版）
    ///
    /// # 参数
    /// - `name`: 规则名称
    /// - `direction`: 方向 ("in" 或 "out")，默认 "in"
    /// - `expected_ips`: 期望的IP列表（支持CIDR、单个IP、IP范围等）
    /// - `strict_mode`: 严格模式（true: 规则中的IP必须完全匹配期望列表；false: 只检查期望IP是否在规则中）
    ///
    /// # 返回值
    /// - `Ok(true)`: 规则存在且所有期望IP都在规则中
    /// - `Ok(false)`: 规则不存在或IP不匹配
    /// - `Err(FirewallError)`: 操作失败
    pub fn verify_rule(
        &self,
        name: &str,
        direction: Option<&str>,
        expected_ips: &[String],
        strict_mode: bool,
    ) -> Result<bool, FirewallError> {
        let direction = direction.unwrap_or("in");

        // 检查规则是否存在
        match self.get_rule_details(name, direction) {
            Ok(rule) => {
                // 获取当前规则的RemoteIP列表
                let current_ips = self.get_rule_remote_ips(name, direction)?;

                // 如果期望IP列表为空，只检查规则是否存在且启用
                if expected_ips.is_empty() {
                    return Ok(rule.enabled);
                }

                // 检查所有期望IP是否都在当前规则中
                let all_expected_match = expected_ips.iter().all(|expected| {
                    self.is_ip_matched(expected, &current_ips)
                });

                if !all_expected_match {
                    return Ok(false);
                }

                // 严格模式：检查规则中的IP是否都在期望列表中
                if strict_mode {
                    let all_current_match = current_ips.iter().all(|current| {
                        expected_ips.iter().any(|expected| {
                            self.ip_match(expected, current)
                        })
                    });
                    return Ok(all_current_match && rule.enabled);
                }

                Ok(rule.enabled)
            }
            Err(FirewallError::RuleNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 验证规则是否包含指定的IP（简化版）
    pub fn verify_rule_simple(
        &self,
        name: &str,
        direction: Option<&str>,
        expected_ip: &str,
    ) -> Result<bool, FirewallError> {
        let direction = direction.unwrap_or("in");

        match self.get_rule_details(name, direction) {
            Ok(rule) => {
                let current_ips = self.get_rule_remote_ips(name, direction)?;
                let matched = self.is_ip_matched(expected_ip, &current_ips);
                Ok(matched && rule.enabled)
            }
            Err(FirewallError::RuleNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 获取规则详情（公开方法）
    pub fn get_rule_info(&self, name: &str, direction: Option<&str>) -> Result<FirewallRule, FirewallError> {
        let direction = direction.unwrap_or("in");
        self.get_rule_details(name, direction)
    }

    /// 检查规则是否存在（公开方法）
    pub fn rule_exists(&self, name: &str, direction: Option<&str>) -> Result<bool, FirewallError> {
        let direction = direction.unwrap_or("in");
        match self.get_rule_details(name, direction) {
            Ok(_) => Ok(true),
            Err(FirewallError::RuleNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 获取规则的RemoteIP列表（公开方法）
    pub fn get_remote_ips(&self, name: &str, direction: Option<&str>) -> Result<Vec<String>, FirewallError> {
        let direction = direction.unwrap_or("in");
        self.get_rule_remote_ips(name, direction)
    }

    /// 比较两个IP列表是否匹配（支持多种格式）
    pub fn compare_ip_lists(&self, expected: &[String], actual: &[String]) -> bool {
        if expected.is_empty() && actual.is_empty() {
            return true;
        }

        if expected.is_empty() || actual.is_empty() {
            return false;
        }

        // 检查所有期望IP是否都在实际列表中
        let all_expected_match = expected.iter().all(|exp| self.is_ip_matched(exp, actual));

        // 检查所有实际IP是否都在期望列表中
        let all_actual_match = actual.iter().all(|act| {
            expected.iter().any(|exp| self.ip_match(exp, act))
        });

        all_expected_match && all_actual_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_to_u32() {
        let firewall = WindowsFirewall::new();
        let parts = [192, 168, 1, 1];
        assert_eq!(firewall.ip_to_u32(&parts), 0xC0A80101);
    }

    #[test]
    fn test_cidr_match() {
        let firewall = WindowsFirewall::new();
        assert!(firewall.cidr_match("192.168.0.0/24", "192.168.0.1"));
        assert!(firewall.cidr_match("192.168.0.0/24", "192.168.0.254"));
        assert!(!firewall.cidr_match("192.168.0.0/24", "192.168.1.1"));
        assert!(firewall.cidr_match("10.0.0.0/8", "10.255.255.255"));
        assert!(!firewall.cidr_match("10.0.0.0/8", "11.0.0.1"));
    }

    #[test]
    fn test_range_match() {
        let firewall = WindowsFirewall::new();
        assert!(firewall.range_match("192.168.0.1-192.168.0.10", "192.168.0.5"));
        assert!(!firewall.range_match("192.168.0.1-192.168.0.10", "192.168.0.20"));
        assert!(firewall.range_match("10.0.0.1-10.0.0.100", "10.0.0.50"));
    }

    #[test]
    fn test_wildcard_match() {
        let firewall = WindowsFirewall::new();
        assert!(firewall.wildcard_match("192.168.*.*", "192.168.1.1"));
        assert!(firewall.wildcard_match("192.168.*.*", "192.168.255.255"));
        assert!(!firewall.wildcard_match("192.168.*.*", "192.169.1.1"));
        assert!(firewall.wildcard_match("*.168.1.*", "192.168.1.100"));
    }

    #[test]
    fn test_ip_match() {
        let firewall = WindowsFirewall::new();
        
        // 完全匹配
        assert!(firewall.ip_match("192.168.1.1", "192.168.1.1"));
        assert!(!firewall.ip_match("192.168.1.1", "192.168.1.2"));
        
        // CIDR匹配
        assert!(firewall.ip_match("192.168.0.0/24", "192.168.0.100"));
        assert!(!firewall.ip_match("192.168.0.0/24", "192.168.1.100"));
        
        // IP范围匹配
        assert!(firewall.ip_match("192.168.0.1-192.168.0.10", "192.168.0.5"));
        assert!(!firewall.ip_match("192.168.0.1-192.168.0.10", "192.168.0.20"));
        
        // 通配符匹配
        assert!(firewall.ip_match("192.168.*.*", "192.168.1.1"));
        assert!(!firewall.ip_match("192.168.*.*", "192.169.1.1"));
        
        // 多IP匹配
        assert!(firewall.ip_match("192.168.0.1,192.168.0.2", "192.168.0.1"));
        assert!(firewall.ip_match("192.168.0.1,192.168.0.2", "192.168.0.2"));
        assert!(!firewall.ip_match("192.168.0.1,192.168.0.2", "192.168.0.3"));
    }

    #[test]
    fn test_is_ip_in_list() {
        let firewall = WindowsFirewall::new();
        let ip_list = vec![
            "192.168.0.0/24".to_string(),
            "10.0.0.1".to_string(),
            "172.16.*.*".to_string(),
        ];

        assert!(firewall.is_ip_in_list("192.168.0.100", &ip_list));
        assert!(firewall.is_ip_in_list("10.0.0.1", &ip_list));
        assert!(firewall.is_ip_in_list("172.16.1.1", &ip_list));
        assert!(!firewall.is_ip_in_list("192.168.1.1", &ip_list));
        assert!(!firewall.is_ip_in_list("10.0.0.2", &ip_list));
    }
}