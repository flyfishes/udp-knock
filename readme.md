# UDP Knock - 安全的远程防火墙管理工具

[![Build Status](https://github.com/yourusername/udp-knock/workflows/Build/badge.svg)](https://github.com/yourusername/udp-knock/actions)
[![Release](https://img.shields.io/github/v/release/yourusername/udp-knock)](https://github.com/yourusername/udp-knock/releases)
[![License](https://img.shields.io/github/license/yourusername/udp-knock)](LICENSE)

## 📋 简介

UDP Knock 是一个使用 Rust 编写的安全 UDP 远程防火墙管理工具。它通过加密的 UDP 数据包实现对防火墙规则的远程管理，特别适合 OpenWrt 等嵌入式设备。

### ✨ 特性

- 🔐 **端到端加密**: 使用 AES-256-GCM 加密所有通信
- 🛡️ **防重放攻击**: 基于时间戳的防重放机制
- 🔌 **多平台支持**: 
  - OpenWrt (aarch64_cortex-a53, ARMv7, x86_64)
  - Linux (iptables/nftables)
  - Windows (Windows Firewall)
- 📦 **轻量级**: 内存占用小，适合嵌入式设备
- 🚀 **高性能**: 基于 Tokio 异步运行时
- 🔧 **易于配置**: JSON 配置文件，支持热重载
- 📊 **防火墙管理**: 支持规则的增删改查和启用/禁用

## 📦 安装

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/yourusername/udp-knock.git
cd udp-knock

# 编译
cargo build --release

# 对于 OpenWrt 平台
cargo build --release --features openwrt --target aarch64-unknown-linux-gnu