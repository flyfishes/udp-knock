# UDP Knock 🛡️

**UDP Knock** 是一个基于 Rust 开发的高性能、安全的远程防火墙管理工具。它通过加密的 UDP 数据包实现远程防火墙规则的管理（开启/关闭/增加/删除/查询），专为 OpenWrt 路由器环境（支持 `fw3` 和 `fw4`）设计，并可扩展支持 Linux 和 Windows 平台。

---

## 🌟 核心特性

- 🔒 **端到端高强度加密**：结合 AES-256-GCM 对对称加密与 HMAC-SHA256 签名，保障通信机密性与防篡改。
- ⏱️ **防重放攻击 (Anti-Replay)**：采用基于 UNIX 时间戳的 30 秒动态时间窗口校验，有效防范重放攻击。
- 🤫 **静默拒绝策略 (Silent Drop)**：对未经授权、解密失败、签名不匹配或时间戳超时的请求静默丢弃，不返回任何响应，隐匿服务器端口。
- 🚀 **原生 OpenWrt 深度集成**：采用 UCI (Unified Configuration Interface) 框架，完美兼容 OpenWrt `fw3` (iptables) 和 `fw4` (nftables)。
- ⚡ **高性能与低资源占用**：Rust 原生编写，单文件静态编译，内存占用 `< 10MB`，UDP 单包响应时间 `< 100ms`。
- 📊 **频率限制与白名单**：内置令牌桶限流算法（默认 60 请求/分钟）及客户端 IP 白名单机制。

---

## 🛡️ 安全架构

```
客户端 (Client)                                          服务端 (Server)
   |                                                        |
   |-- 1. 构建 JSON 命令 + 时间戳                             |
   |-- 2. AES-256-GCM 加密                                   |
   |-- 3. HMAC-SHA256 签名                                   |
   |-- 4. Base64 编码 UDP 数据包 -------------------------->|
   |                                                        |-- 5. IP 白名单 & 限流检查
   |                                                        |-- 6. 验证 HMAC 签名
   |                                                        |-- 7. AES-256-GCM 解密
   |                                                        |-- 8. 校验 30s 时间窗口
   |                                                        |-- 9. 执行 UCI 防火墙命令
   |<-- 10. 加密响应 (JSON) ---------------------------------|
```

### 密钥派生方案
为了防止跨协议密钥复用，由共享密钥 (PSK) 通过 SHA-256 分别派生加密密钥与认证密钥：
- **加密密钥 (`AES_KEY`)**: `SHA256(PSK + ":aes-key")`
- **认证密钥 (`HMAC_KEY`)**: `SHA256(PSK + ":hmac-key")`

---

## 🚀 快速开始

### 1. 编译安装

需求：Rust 1.75+ 环境。

```bash
# 克隆仓库
git clone https://github.com/flyfishes/udp-knock.git
cd udp-knock

# 本地编译
cargo build --release --features openwrt
```

二进制文件将生成于 `target/release/udp-knock`。

---

## ⚙️ 配置文件说明

运行 `udp-knock init` 可生成默认配置文件 `config.json`：

```bash
udp-knock init --platform openwrt
```

`config.json` 示例：

```json
{
  "server": {
    "bind_addr": "0.0.0.0:9999",
    "shared_key": "your_custom_secret_key_here",
    "allowed_ips": [],
    "rate_limit": 60
  },
  "client": {
    "server_addr": "192.168.1.1:9999",
    "shared_key": "your_custom_secret_key_here",
    "timeout": 5
  },
  "platform": "openwrt",
  "debug": false
}
```

---

## 📖 命令行使用说明

### 1. 全局选项

```bash
udp-knock [OPTIONS] <COMMAND>
```

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config <FILE>` | 指定配置文件路径 | `config.json` |
| `-d, --debug` | 启用调试输出日志 | `false` |
| `-p, --platform <PLATFORM>`| 强制指定运行平台 (`openwrt`, `linux`, `windows`) | `openwrt` |

---

### 2. 启动服务端 (`server`)

在 OpenWrt 路由器上之后后台运行服务端：

```bash
# 调试模式运行
udp-knock -d server

# 后台静默运行
nohup udp-knock server > /dev/null 2>&1 &
```

---

### 3. 客户端命令发送 (`client`)

```bash
udp-knock client [OPTIONS]
```

#### ① 列出当前防火墙规则 (`list` & 分页 ` -n`)
```bash
# 默认从第 0 条开始查询（自动包含下一页提示）
udp-knock client -a list

# 指定从第 25 条开始分页查询
udp-knock client -a list -n 25

# 结合关键字筛选并分页
udp-knock client -a list -p rule -n 10
```

#### ② 启用/禁用指定防火墙规则 (`enable` / `disable`)
```bash
# 启用名为 rule_ssh 的规则
udp-knock client -a enable -p rule_ssh

# 禁用名为 rule_ssh 的规则
udp-knock client -a disable -p rule_ssh
```

#### ③ 创建新规则 (`create`)
格式：`create <规则名> <源区域> <目标区域> <协议> <端口>`
```bash
# 创建允许 WAN 访问 LAN 80 端口的网页访问规则
udp-knock client -a create -p rule_web wan lan tcp 80
```

#### ④ 删除规则 (`delete`)
```bash
udp-knock client -a delete -p rule_web
```

#### ⑤ 查询防火墙总体状态 (`status`)
```bash
udp-knock client -a status
```

---

### 4. 本地防火墙状态查看 (`status`)

直连查询当前路由器的防火墙状态：

```bash
udp-knock status
```

输出示例：
```text
Firewall Status:
  Platform: OpenWrt
  Active: true
  Total Rules: 12
  Active Rules: 10
```

---

## 🌐 OpenWrt 部署与交叉编译

可以使用 `cross` 工具针对 OpenWrt 架构进行交叉编译：

```bash
# 安装 cross 工具
cargo install cross --git https://github.com/cross-rs/cross --locked

# 为 ARM64 (aarch64) OpenWrt 路由器编译
cross build --release --target aarch64-unknown-linux-musl --features openwrt

# 为 x86_64 OpenWrt 路由器编译
cross build --release --target x86_64-unknown-linux-musl --features openwrt
```

---

## 🤖 GitHub Actions CI/CD

本项目已配置完整的 GitHub Actions 工作流（位于 `.github/workflows/build.yml`）：
- 每次提交代码自动执行代码规范格式校验 (`cargo fmt`)、静态代码 Lint (`cargo clippy`) 及全功能单元测试。
- 推送 `v*` 版本的 Git Tag 时自动触发 ARM64/x86_64 多平台交叉构建、UPX 压缩并发布至 GitHub Release。

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 协议开源。
