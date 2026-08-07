// src/server/handler.rs

use crate::config::Config;
use crate::crypto::Security;
use crate::firewall::{FirewallManager, FirewallRule, FirewallResponse};
use log::{debug, error};
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[derive(Debug, serde::Deserialize)]
struct Command {
    action: String,
    params: Vec<String>,
}

pub async fn handle_request(
    config: &Config,
    security: &Security,
    firewall: &dyn FirewallManager,
    data_str: String,
    src_addr: SocketAddr,
    socket: &UdpSocket,
) {
    // 解密消息
    let command_bytes = match security.decrypt_message(&data_str) {
        Ok(bytes) => bytes,
        Err(e) => {
            if config.debug {
                debug!("解密来自 {} 的消息失败: {}", src_addr, e);
            }
            return;
        }
    };

    // 解析命令
    let command_str = match String::from_utf8(command_bytes) {
        Ok(s) => s,
        Err(_) => {
            if config.debug {
                debug!("来自 {} 的命令不是有效的UTF-8", src_addr);
            }
            return;
        }
    };

    if config.debug {
        debug!("收到来自 {} 的命令: {}", src_addr, command_str);
    }

    // 解析JSON命令
    let command: Command = match serde_json::from_str(&command_str) {
        Ok(cmd) => cmd,
        Err(e) => {
            if config.debug {
                debug!("解析来自 {} 的命令失败: {}", src_addr, e);
            }
            let response = json!({
                "success": false,
                "message": format!("命令格式错误: {}", e),
            });
            send_response(security, socket, &response.to_string(), src_addr, config).await;
            return;
        }
    };

    // 执行命令
    let response = execute_command(firewall, command, config).await;

    // 发送响应
    let response_json = json!({
        "success": response.success,
        "message": response.message,
        "rules": response.rules,
        "status": response.status,
    });

    send_response(security, socket, &response_json.to_string(), src_addr, config).await;
}

async fn execute_command(
    firewall: &dyn FirewallManager,
    command: Command,
    config: &Config,
) -> FirewallResponse {
    match command.action.as_str() {
        "list" => {
            match firewall.list_rules() {
                Ok(rules) => FirewallResponse {
                    success: true,
                    message: "规则列表获取成功".to_string(),
                    rules: Some(rules),
                    status: None,
                },
                Err(e) => FirewallResponse {
                    success: false,
                    message: format!("获取规则列表失败: {}", e),
                    rules: None,
                    status: None,
                },
            }
        }
        "enable" => {
            if command.params.is_empty() {
                return FirewallResponse {
                    success: false,
                    message: "缺少规则名".to_string(),
                    rules: None,
                    status: None,
                };
            }
            match firewall.enable_rule(&command.params[0]) {
                Ok(response) => response,
                Err(e) => FirewallResponse {
                    success: false,
                    message: format!("启用规则失败: {}", e),
                    rules: None,
                    status: None,
                },
            }
        }
        "disable" => {
            if command.params.is_empty() {
                return FirewallResponse {
                    success: false,
                    message: "缺少规则名".to_string(),
                    rules: None,
                    status: None,
                };
            }
            match firewall.disable_rule(&command.params[0]) {
                Ok(response) => response,
                Err(e) => FirewallResponse {
                    success: false,
                    message: format!("禁用规则失败: {}", e),
                    rules: None,
                    status: None,
                },
            }
        }
        "create" => {
            if command.params.len() < 5 {
                return FirewallResponse {
                    success: false,
                    message: "参数不足: 需要 name, src, dest, proto, ports".to_string(),
                    rules: None,
                    status: None,
                };
            }
            
            let rule = FirewallRule {
                name: command.params[0].clone(),
                src: command.params[1].clone(),
                dest: command.params[2].clone(),
                proto: command.params[3].clone(),
                ports: command.params[4].clone(),
                enabled: true,
                target: "ACCEPT".to_string(),
                description: if command.params.len() > 5 {
                    command.params[5].clone()
                } else {
                    String::new()
                },
            };

            match firewall.create_rule(&rule) {
                Ok(response) => response,
                Err(e) => FirewallResponse {
                    success: false,
                    message: format!("创建规则失败: {}", e),
                    rules: None,
                    status: None,
                },
            }
        }
        "delete" => {
            if command.params.is_empty() {
                return FirewallResponse {
                    success: false,
                    message: "缺少规则名".to_string(),
                    rules: None,
                    status: None,
                };
            }
            match firewall.delete_rule(&command.params[0]) {
                Ok(response) => response,
                Err(e) => FirewallResponse {
                    success: false,
                    message: format!("删除规则失败: {}", e),
                    rules: None,
                    status: None,
                },
            }
        }
        "status" => {
            match firewall.get_status() {
                Ok(status) => FirewallResponse {
                    success: true,
                    message: "状态获取成功".to_string(),
                    rules: None,
                    status: Some(status),
                },
                Err(e) => FirewallResponse {
                    success: false,
                    message: format!("获取状态失败: {}", e),
                    rules: None,
                    status: None,
                },
            }
        }
        _ => {
            FirewallResponse {
                success: false,
                message: format!("未知命令: {}", command.action),
                rules: None,
                status: None,
            }
        }
    }
}

async fn send_response(
    security: &Security,
    socket: &UdpSocket,
    response: &str,
    target_addr: SocketAddr,
    config: &Config,
) {
    match security.encrypt_message(response.as_bytes()) {
        Ok(encrypted) => {
            if let Err(e) = socket.send_to(encrypted.as_bytes(), target_addr).await {
                error!("发送响应到 {} 失败: {}", target_addr, e);
            } else if config.debug {
                debug!("已发送响应到 {}", target_addr);
            }
        }
        Err(e) => {
            error!("加密响应失败: {}", e);
        }
    }
}