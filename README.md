# Exa Pool

基于 Cloudflare Workers 的 Exa API 密钥负载均衡器，支持多密钥轮询、自动故障转移和可视化管理面板。
<img width="1327" height="793" alt="image" src="https://github.com/user-attachments/assets/9743b3b5-f65e-4eda-b9d5-f07f3f5281fb" />

## 功能特性

- **密钥轮询** - Round-robin 策略自动分配请求到不同 API 密钥
- **自动故障转移** - 密钥余额耗尽或失效时自动切换到下一个可用密钥
- **智能重试** - 请求失败自动重试（最多 3 次）
- **密钥状态管理** - 自动标记耗尽/失效密钥，支持批量验证
- **访问控制** - 通过 Allowed Keys 控制谁可以使用代理服务
- **可视化面板** - Web 管理界面，实时查看密钥状态和请求统计
- **完整 API 兼容** - 兼容 Exa 官方 API

## 支持的 API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/search` | POST | 搜索查询 |
| `/contents` | POST | 获取页面内容 |
| `/findSimilar` | POST | 查找相似链接 |
| `/answer` | POST | AI 问答（支持流式响应） |

## 快速开始

### 一. 新建D1数据库并初始化
1. 进入到[CloudFlare控制台](https://dash.cloudflare.com/)，在存储和数据库-D1 SQL数据库下新建一个名为```exa-pool```的数据库
<img width="1428" height="735" alt="image" src="https://github.com/user-attachments/assets/893ff983-6e01-4edc-ac43-6fc1d432a8bc" />
2. 然后在控制台执行这段命令初始化数据库

 ``` 
 CREATE TABLE IF NOT EXISTS exa_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, status TEXT DEFAULT 'active' CHECK(status IN ('active', 'exhausted', 'invalid')), last_used TEXT, created_at TEXT DEFAULT (datetime('now')), error_message TEXT, success_count INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS allowed_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, name TEXT, created_at TEXT DEFAULT (datetime('now'))); CREATE TABLE IF NOT EXISTS request_stats (id INTEGER PRIMARY KEY CHECK(id = 1), total_success INTEGER DEFAULT 0, total_failure INTEGER DEFAULT 0); INSERT OR IGNORE INTO request_stats (id, total_success, total_failure) VALUES (1, 0, 0); CREATE TABLE IF NOT EXISTS round_robin_state (id INTEGER PRIMARY KEY CHECK(id = 1), last_key_id INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT OR IGNORE INTO round_robin_state (id, last_key_id) VALUES (1, 0); CREATE INDEX IF NOT EXISTS idx_exa_keys_status ON exa_keys(status); CREATE INDEX IF NOT EXISTS idx_allowed_keys_key ON allowed_keys(key);
```
<img width="1652" height="686" alt="image" src="https://github.com/user-attachments/assets/97003169-2186-4dfb-9d2c-19df2dbaf29a" />

### 二. 新建cloudflare worker并配置环境变量
1. 转到cloudflare控制面板的workers-and-pages一栏，点击右上角的创建应用程序并新建一个worker
2. 将本项目的[worker.js](https://github.com/chengtx809/exa-pool/blob/main/worker.js)文件内容复制并粘贴进worker，保存并部署
3. 在 Cloudflare Dashboard 的 Workers 设置中配置下列环境变量：

| 变量名 | 类型 | 说明 | 示例 |
|--------|------|------|------|
| `ADMIN_KEY` | 必填 | 管理面板登录密码 | `your-secure-password` |
| `VALIDATION_CONCURRENCY` | 选填 | 批量验证密钥的并发数 | `10` (默认)

### 三. 连接D1数据库
在worker的“绑定”一栏添加D1数据库并命名为```DB```
<img width="988" height="522" alt="image" src="https://github.com/user-attachments/assets/d083e3fd-4177-43db-9040-dd8edda48a29" />

### 四. 开始使用！

1. 访问 Worker URL 进入管理面板
2. 使用 `ADMIN_KEY` 登录
3. 添加 Exa API 密钥
4. 创建 Exa Pool 请求密钥用于 API 访问

## API 使用（与Exa官方同步）

### 认证方式

```bash
# x-api-key header
curl -H "x-api-key: YOUR_ALLOWED_KEY" ...

# 或 Authorization header
curl -H "Authorization: Bearer YOUR_ALLOWED_KEY" ...
```

### 搜索

```bash
curl -X POST 'https://your-worker.workers.dev/search' \
  -H 'x-api-key: YOUR_ALLOWED_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "Latest AI research",
    "numResults": 10
  }'
```

### 获取内容

```bash
curl -X POST 'https://your-worker.workers.dev/contents' \
  -H 'x-api-key: YOUR_ALLOWED_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "urls": ["https://example.com"],
    "text": true
  }'
```

### 查找相似链接

```bash
curl -X POST 'https://your-worker.workers.dev/findSimilar' \
  -H 'x-api-key: YOUR_ALLOWED_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://arxiv.org/abs/2307.06435",
    "numResults": 10
  }'
```

### AI 问答

```bash
curl -X POST 'https://your-worker.workers.dev/answer' \
  -H 'x-api-key: YOUR_ALLOWED_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "What is the latest valuation of SpaceX?",
    "text": true
  }'
```

## 管理面板

访问 Worker 根路径 (`/`) 进入管理面板：

- **Exa 密钥管理** - 添加、删除、验证 API 密钥
- **访问密钥管理** - 管理允许访问代理的 API Key
- **状态监控** - 查看密钥状态分布和请求统计
- **批量操作** - 批量添加密钥、清理失效密钥

## 密钥状态

| 状态 | 说明 |
|------|------|
| `active` | 正常可用 |
| `exhausted` | 余额耗尽 |
| `invalid` | 密钥无效 |

## 技术栈

- Cloudflare Workers
- Cloudflare D1 (SQLite)
- Vanilla JavaScript (管理面板)

## License

MIT
