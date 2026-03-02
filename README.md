# WeChat macOS Database Decryptor

微信 3.8.x (macOS) 本地数据库解密与实时监听工具。通过 Mach API 扫描微信进程内存提取 SQLCipher 3 raw key，解密本地数据库，并提供实时消息监听和 Claude AI 集成。

## 原理

微信 3.8.x (macOS) 使用 SQLCipher 3 加密本地数据库：

- **加密算法**: AES-256-CBC + HMAC-SHA1
- **KDF**: PBKDF2-HMAC-SHA1, 64,000 iterations
- **页面大小**: 1024 bytes, reserve = 48 (IV 16 + HMAC 20 + pad 12)
- **每个数据库有独立的 salt 和 enc_key**

WCDB 会在进程内存中缓存派生后的 raw key，格式为 `x'<64hex_enc_key><32hex_salt>'`。本工具通过 macOS Mach API 扫描进程内存中的这种模式，匹配数据库文件的 salt，并通过 HMAC 验证提取正确的密钥。

## 环境要求

- macOS (Apple Silicon)
- Python 3.10+
- 微信 3.8.x (正在运行)
- SIP 关闭 (`csrutil disable`)
- `sudo` 权限 (读取进程内存需要 `task_for_pid`)

## 安装依赖

```bash
pip install pycryptodome
pip install mcp  # 仅 MCP Server 需要
```

## 使用方法

### 1. 配置

首次运行任意脚本会自动生成 `config.json` 模板：

```json
{
    "db_dir": "~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9/<user_hash>",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "WeChat"
}
```

将 `db_dir` 中的 `<user_hash>` 替换为实际路径（可在 `~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9/` 下找到）。

### 2. 提取密钥

确保微信正在运行，关闭 SIP 后以 `sudo` 运行：

```bash
sudo python find_all_keys.py
```

密钥将保存到 `all_keys.json`。

### 3. 解密数据库

```bash
python decrypt_db.py
```

解密后的数据库保存在 `decrypted/` 目录，可直接用 SQLite 工具打开。

### 4. 实时消息监听

#### Web UI (推荐)

```bash
python monitor_web.py
```

打开 http://localhost:5678 查看实时消息流。

- 30ms 轮询 WAL 文件变化 (mtime)
- 检测到变化后全量解密 + WAL patch
- SSE 实时推送到浏览器

#### 命令行

```bash
python monitor.py
```

每 3 秒轮询一次，在终端显示新消息。

### 5. MCP Server (Claude AI 集成)

将微信数据查询能力接入 [Claude Code](https://claude.ai/claude-code)，让 AI 直接读取你的微信消息。

注册到 Claude Code：

```bash
claude mcp add wechat -- python /path/to/wechat-decrypt/mcp_server.py
```

或手动编辑 `~/.claude.json`：

```json
{
  "mcpServers": {
    "wechat": {
      "type": "stdio",
      "command": "python",
      "args": ["/path/to/wechat-decrypt/mcp_server.py"]
    }
  }
}
```

注册后在 Claude Code 中即可使用以下工具：

| Tool | 功能 | 来源 ｜
|------|------|------|
| `get_recent_sessions(limit)` | 最近会话列表，每个会话的最新一条消息（含消息摘要、未读数） | session_new.db + WAL |
| `get_chat_history(chat_name, limit, start_time, end_time)` | 指定聊天的消息记录（支持模糊匹配名字和按时间范围过滤） | msg_x.db + WAL |
| `search_messages(keyword, limit, start_time, end_time)` | 全库搜索消息内容（支持按时间范围过滤） | msg0-9 + WAL |
| `get_contacts(query, limit)` | 搜索/列出联系人 | wccontact_new2.db |
| `get_new_messages()` | 获取自上次调用以来的新消息 | session_new.db + WAL |

前置条件：需要先完成步骤 1-2（配置 + 提取密钥）。

时间过滤参数说明：

- `start_time` / `end_time` 都是可选参数
- 支持格式：`YYYY-MM-DD`、`YYYY-MM-DD HH:MM`、`YYYY-MM-DD HH:MM:SS`
- `YYYY-MM-DD` 会自动扩展到当天开始或结束时间
- 推荐让模型把“最近一周”“最近一月”这类自然语言转换成具体日期后再调用 MCP 方法

## 文件说明

| 文件 | 说明 |
|------|------|
| `config.py` | 配置加载器，支持 `~` 和相对路径 |
| `crypto_params.py` | SQLCipher 3 解密原语和加密常量 |
| `find_all_keys.py` | 通过 macOS Mach API 扫描进程内存提取密钥 |
| `decrypt_db.py` | 全量解密所有数据库到 `decrypted/` |
| `mcp_server.py` | MCP Server，让 Claude AI 查询微信数据 |
| `monitor_web.py` | 实时消息监听 (Web UI + SSE) |
| `monitor.py` | 实时消息监听 (命令行) |
| `latency_test.py` | 延迟测量诊断工具 |

## 技术细节

### macOS Mach API

- `task_for_pid` 需要 `sudo` + SIP 关闭
- `mach_vm_region` + `vm_region_basic_info_64` 枚举内存区域
- `mach_vm_read_overwrite` 读取内存
- 双策略搜索：主策略 `x'<hex>'` 正则匹配 + fallback raw salt 扫描

### WAL 处理

微信使用预分配固定大小的 WAL 文件，不能用文件大小检测变化，必须用 mtime。解密 WAL frame 时需校验 frame salt 与 WAL header salt 一致，跳过旧周期遗留的 frame。

### 数据库结构 (3.8.x macOS)

- `Session/session_new.db` - 会话列表
- `Message/msg_N.db` - 聊天记录，每个联系人对应表 `Msg_<md5(username)>`
- `Contact/wccontact_new2.db` - 联系人

## 免责声明

本工具仅用于学习和研究目的，用于解密**自己的**微信数据。请遵守相关法律法规，不要用于未经授权的数据访问。
