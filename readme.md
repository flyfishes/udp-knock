# UDP Knock - 安全的远程防火墙管理工具

[![Build Status](https://github.com/yourusername/udp-knock/workflows/Build/badge.svg)](https://github.com/yourusername/udp-knock/actions)
[![License](https://img.shields.io/github/license/yourusername/udp-knock)](LICENSE)

## 📋 简介

UDP Knock 是一个使用 Rust 编写的安全 UDP 远程防火墙管理工具。它通过加密的 UDP 数据包实现对防火墙规则的远程管理，特别适合 OpenWrt 等嵌入式设备。

### ✨ 特性

- 🔐 **端到端加密**: 使用 AES-256-GCM 加密所有通信
- 🛡️ **防重放攻击**: 基于时间戳的防重放机制
- 🔌 **多平台支持**: 
  - OpenWrt (aarch64_cortex-a53, x86_64)
  - Linux (占位实现)
  - Windows (占位实现)
- 📦 **轻量级**: 内存占用小，适合嵌入式设备
- 🚀 **高性能**: 基于 Tokio 异步运行时

## 📦 安装

### 从源码编译

```bash
git clone https://github.com/yourusername/udp-knock.git
cd udp-knock
cargo build --release --features openwrt
```

### 从 Release 下载
从 Release 页面 下载对应平台的二进制文件。

##🚀 快速开始
1. 生成配置文件
bash
./udp-knock init --platform openwrt
2. 编辑配置文件
修改 config.json 中的 shared_key：

json
{
  "security": {
    "shared_key": "your_strong_secret_key_here"
  }
}
3. 启动服务端
bash
./udp-knock server
4. 客户端命令
bash
# 列出所有规则
./udp-knock client --action list

# 启用规则
./udp-knock client --action enable --params "web_forward"

# 创建规则
./udp-knock client --action create --params "web_forward" "lan" "wan" "tcp" "80"

# 删除规则
./udp-knock client --action delete --params "web_forward"
📁 项目结构
text
udp-knock/
├── .github/          # GitHub Actions
├── src/
│   ├── config/       # 配置管理
│   ├── crypto/       # 加密模块
│   ├── firewall/     # 防火墙适配层
│   ├── server/       # 服务端
│   └── client/       # 客户端
├── Cargo.toml
└── config.json.example
📄 许可证
MIT License

text

---

## 22. LICENSE

```txt
MIT License

Copyright (c) 2024 Your Name

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.