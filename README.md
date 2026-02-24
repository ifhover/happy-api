# kiro-api-proxy

将 Kiro 的 AI 能力转换为兼容 OpenAI / Claude 格式的 API 代理服务，支持多 token 管理、自动刷新和配额轮询。

## 功能

- 兼容 OpenAI (`/v1/chat/completions`) 和 Claude (`/v1/messages`) 接口格式
- 支持流式和非流式响应
- 多 token 轮询，自动跳过低配额 token
- Token 自动刷新（过期前 30 分钟）
- Web 管理界面，支持添加、删除、启用/禁用 token
- 支持 HTTP 代理、IP 白名单

## 下载

前往 [Releases](../../releases) 页面下载对应平台的二进制文件：

| 平台 | 文件名 |
|------|--------|
| macOS (Apple Silicon) | `kiro-api-proxy-darwin-arm64` |
| macOS (Intel) | `kiro-api-proxy-darwin-amd64` |
| Linux (x86_64) | `kiro-api-proxy-linux-amd64` |
| Linux (ARM64) | `kiro-api-proxy-linux-arm64` |
| Windows | `kiro-api-proxy-windows-amd64.exe` |

## 使用

### macOS / Linux

```bash
# 添加执行权限
chmod +x kiro-api-proxy-darwin-arm64

# 运行（首次运行自动生成 config.json）
./kiro-api-proxy-darwin-arm64
```

macOS 如果提示"无法验证开发者"：

```bash
xattr -d com.apple.quarantine kiro-api-proxy-darwin-arm64
```

### Windows

直接双击 `.exe` 或在命令行运行即可。

---

启动后访问 `http://localhost:8080` 打开 Web 管理界面，添加 token 后即可使用。

## 配置

首次运行自动生成 `config.json`，可在 Web 界面或直接编辑文件修改：

```json
{
  "host": "0.0.0.0",
  "port": "8080",
  "api_key": "your-api-key",
  "allowed_ips": [],
  "min_quota_remaining": 0,
  "proxy_url": ""
}
```

| 字段 | 说明 |
|------|------|
| `host` | 监听地址，`0.0.0.0` 表示监听所有网卡 |
| `port` | 监听端口 |
| `api_key` | 调用代理接口时需要提供的密钥 |
| `allowed_ips` | 管理界面 IP 白名单，空数组表示不限制，支持 CIDR 格式 |
| `min_quota_remaining` | 最低剩余配额阈值，低于此值的 token 不优先使用，`0` 表示不限制 |
| `proxy_url` | HTTP 代理地址，留空使用系统代理 |

## 添加 Token

在 Web 管理界面（`http://localhost:8080`）中添加 token，支持以下方式：

- **Social Auth**：通过 Google / GitHub 账号授权
- **Builder ID**：通过 AWS Builder ID（IdC）授权
- **手动导入**：直接粘贴 `kiro-auth-token.json` 文件内容批量导入

## 调用

服务启动后，将客户端的 API 地址指向本服务即可。

**OpenAI 格式：**

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-5",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

**Claude 格式：**

```bash
curl http://localhost:8080/v1/messages \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-5",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

## 从源码构建

需要 Go 1.21+：

```bash
git clone https://github.com/你的用户名/kiro-api-proxy.git
cd kiro-api-proxy
go build -o kiro-api-proxy .
```
