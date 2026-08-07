// src/client/command.rs

use crate::config::Config;
use crate::crypto::Security;
use log::debug;
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub async fn send_command(
    config: &Config,
    security: &Security,
    socket: &UdpSocket,
    action: &str,
    params: &[String],
) -> Result<String, String> {
    // 构造JSON命令
    let command = json!({
        "action": action,
        "params": params,
    });

    let command_str = command.to_string();
    debug!("发送命令: {}", command_str);

    // 加密命令
    let encrypted = match security.encrypt_message(command_str.as_bytes()) {
        Ok(data) => data,
        Err(e) => return Err(format!("加密失败: {}", e)),
    };

    // 发送到服务器
    let server_addr = config.client.server_addr;
    if let Err(e) = socket.send_to(encrypted.as_bytes(), server_addr).await {
        return Err(format!("发送失败: {}", e));
    }

    debug!("已发送命令到 {}，等待响应...", server_addr);

    // 接收响应（带超时）
    let mut buf = vec![0u8; config.security.max_packet_size];
    let timeout_duration = Duration::from_secs(config.client.timeout_secs);

    match timeout(timeout_duration, socket.recv_from(&mut buf)).await {
        Ok(Ok((size, _src_addr))) => {
            let data = &buf[..size];
            let data_str = String::from_utf8_lossy(data);

            debug!("收到响应: {}", data_str);

            // 解密响应
            match security.decrypt_message(&data_str) {
                Ok(response_bytes) => {
                    match String::from_utf8(response_bytes) {
                        Ok(response_str) => {
                            // 解析JSON响应
                            let response: serde_json::Value = 
                                serde_json::from_str(&response_str)
                                    .map_err(|e| format!("解析响应失败: {}", e))?;
                            
                            if let Some(success) = response.get("success").and_then(|v| v.as_bool()) {
                                if success {
                                    Ok(response_str)
                                } else {
                                    let msg = response.get("message")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("操作失败（无详细信息）");
                                    Err(msg.to_string())
                                }
                            } else {
                                Err("响应格式错误".to_string())
                            }
                        }
                        Err(e) => Err(format!("响应不是有效的UTF-8: {}", e)),
                    }
                }
                Err(e) => Err(format!("解密响应失败: {}", e)),
            }
        }
        Ok(Err(e)) => Err(format!("接收响应失败: {}", e)),
        Err(_) => Err("接收响应超时".to_string()),
    }
}