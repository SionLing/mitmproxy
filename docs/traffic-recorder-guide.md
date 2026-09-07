# 流量采集与分析使用文档

基于 mitmproxy + `recorder/` 工具集，将代理流量全量落盘到 SQLite，供 Claude Code 实时查询、域名过滤与请求/响应分析。

## 目录

1. [环境准备](#1-环境准备)
2. [CA 证书安装](#2-ca-证书安装)
3. [客户端代理配置](#3-客户端代理配置)
4. [手机抓包](#4-手机抓包)
5. [启动采集](#5-启动采集)
6. [数据库结构](#6-数据库结构)
7. [查询与分析](#7-查询与分析)
8. [Claude Code 集成](#8-claude-code-集成)
9. [主动告警](#9-主动告警)
10. [常见问题](#10-常见问题)

---

## 1. 环境准备

```shell
# 安装 uv（任选其一）
curl -LsSf https://astral.sh/uv/install.sh | sh
brew install uv

# 验证（uv run 会自动创建 .venv 并安装全部依赖）
cd /Users/sion/projects/mitmproxy
uv run mitmproxy --version
```

依赖说明：采集 addon 只用 Python 标准库（`sqlite3`/`json`），无额外依赖；MCP server 的 `mcp` 依赖通过 PEP 723 inline metadata 声明，`uv run --script` 时自动安装，不污染项目环境。

## 2. CA 证书安装

解密 HTTPS 必须让客户端信任 mitmproxy 的 CA（首次启动 mitmproxy 时自动生成于 `~/.mitmproxy/`）。

### 推荐：通过 mitm.it 安装

1. 启动 `mitmproxy` 或 `mitmweb`
2. 把浏览器代理指向 `127.0.0.1:8080`
3. 访问 `http://mitm.it`（注意是 http；此页面由代理本身提供，不走外网），按系统图标下载安装

### macOS 手动安装

```shell
open ~/.mitmproxy/
# 双击 mitmproxy-ca-cert.pem 导入钥匙串
# 钥匙串访问 → 找到 mitmproxy → 双击 → 信任 → 始终信任
```

### 其他平台

| 平台 | 方式 |
|------|------|
| Windows | 双击 `mitmproxy-ca-cert.p12`，导入「受信任的根证书颁发机构」 |
| Linux | 复制 `mitmproxy-ca-cert.pem` 为 `.crt` 到 `/usr/local/share/ca-certificates/`，运行 `sudo update-ca-certificates` |
| iOS | 访问 mitm.it 安装描述文件后，到 设置 → 通用 → 关于本机 → 证书信任设置 启用完全信任 |
| Android | mitm.it 下载安装；Android 7+ 应用默认不信任用户证书，需目标应用允许或 root 后装入系统证书区 |
| Firefox | 使用独立证书库：设置 → 隐私与安全 → 证书 → 导入 `~/.mitmproxy/mitmproxy-ca-cert.pem` |

### 验证

```shell
curl -x http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com
```

## 3. 客户端代理配置

### 命令行工具

```shell
# curl
curl -x http://127.0.0.1:8080 https://example.com

# ⚠️ 本机环境的 NO_PROXY 包含 127.0.0.1，访问本地服务时 curl 会绕过代理，
# 必须显式清空：
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:18080/api
```

### macOS 系统代理

```shell
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080

# 关闭
networksetup -setwebproxystate Wi-Fi off
networksetup -setsecurewebproxystate Wi-Fi off
```

或在 系统设置 → Wi-Fi → 详细信息 → 代理 中手动配置。

## 4. 手机抓包

### 方式选择

| | 手动代理模式 | WireGuard 模式 |
|---|---|---|
| 工作层级 | 应用层（App 自愿走代理） | 网络层（VPN 隧道，强制接管全部流量） |
| 手机设置 | Wi-Fi → 手动代理 | 关闭代理，用 WireGuard App 连隧道 |
| 抓包范围 | 只有遵守系统代理的 App | **所有 TCP/UDP 流量**，含绕过代理的 SDK |
| 适用场景 | 日常抓包、浏览器、普通 App | 分析有反抓包设计的 SDK（如广告聚合平台） |
| 性能影响 | 仅代理 App 受影响 | 手机全部流量绕行 Mac，视频类明显变慢 |

### 4.1 手动代理模式（日常推荐）

```shell
# Mac 上启动：监听局域网、不动 Mac 系统代理，并打印本机局域网 IP
recorder/capture.sh start --phone
```

手机端：

1. 手机与 Mac 连**同一个 Wi-Fi**
2. 手机 Wi-Fi 详情 → 代理 → 手动 → 服务器填 Mac 的局域网 IP（如 `192.168.1.163`），端口 `8080`
3. 首次使用：浏览器访问 `http://mitm.it` 安装 CA 证书
   - iOS 还需：设置 → 通用 → 关于本机 → **证书信任设置** → 启用完全信任
   - Android 7+：用户证书只对浏览器生效，App 的 HTTPS 需其自身允许用户证书
4. 如果 Mac 防火墙弹出「是否允许接受传入连接」，选允许

**视频/大文件变慢的优化**：手机流量会经 Mac 的 VPN 出口绕行。在 Android 代理设置的「对以下网址不使用代理」（Bypass proxy for）中填入媒体 CDN 域名即可直连加速，例如：

```
good-videos.net, octomax.net
```

### 4.2 WireGuard 模式（抓绕过系统代理的 SDK）

部分 SDK（如 TopOn 等广告聚合平台）使用自有 DoH（直接向 dns.google 查询域名）+ 直连 socket，**刻意绕过系统代理**，手动代理模式完全抓不到它们的请求。WireGuard 模式从网络层接管，App 无法绕过。

启动（注意两个 `--mode` 都要显式写）：

```shell
# 方式一：capture.sh 统一入口（推荐，自动打印 Web UI 地址和修正提示）
recorder/capture.sh start --wireguard

# 方式二：手动命令
uv run mitmweb --mode regular --mode wireguard -s recorder/traffic_recorder.py
```

> ⚠️ 踩过的坑：**不要加 `-p 8080`**。`-p` 会作为所有模式的默认端口，WireGuard 会抢占 8080 导致常规代理无法启动。显式写 `--mode regular --mode wireguard` 后默认端口分别是 8080 和 51820，互不冲突。

手机端步骤：

1. **先关闭 Wi-Fi 的手动代理**（两种模式互斥，留着会导致 App 把请求发给已不存在的代理服务）
2. 安装 **WireGuard** App
3. 打开 mitmweb 界面（启动日志中带 token 的 `http://127.0.0.1:8081/?token=...`），在 WireGuard 模式卡片上找到**二维码**
4. WireGuard App → 添加隧道 → 扫描二维码（Tunnel name 随便填，只是本地显示名）
5. **必须手动修正 Endpoint**：若 Mac 开着 VPN，mitmproxy 会把 Endpoint 误识别为 VPN 隧道 IP。在 WireGuard App 里编辑该隧道，把 Endpoint 改为 **Mac 局域网 IP + 51820**（如 `192.168.1.163:51820`），保存并启用

验证手机已接入：

```shell
sqlite3 recorder/traffic.db \
  "SELECT host, count(*) FROM flows WHERE ts > unixepoch() - 300 GROUP BY host"
```

手机上随便操作，几秒后应出现新记录。

**用完记得切回**：WireGuard 模式下手机所有流量走 Mac → VPN 出口，视频 App 会明显变慢。分析完毕后停掉（`pkill mitmweb`），日常抓包用 `recorder/capture.sh start --phone`。

## 5. 启动采集

```shell
cd /Users/sion/projects/mitmproxy

# 纯采集（推荐日常后台运行）
uv run mitmdump -s recorder/traffic_recorder.py

# 同时需要 Web UI 查看流量
uv run mitmweb -s recorder/traffic_recorder.py

# 自定义数据库位置
uv run mitmdump -s recorder/traffic_recorder.py --set traffic_db=/path/to/traffic.db

# 其他监听端口
uv run mitmdump -p 9090 -s recorder/traffic_recorder.py
```

行为约定：

- **全量记录**：所有 HTTP/HTTPS 请求（含失败的连接）都落盘，域名过滤在查询时做
- **body 策略**：文本类（json/html/xml/text/form 等）存明文并截断到 256KB；二进制只存大小
- **gzip/brotli**：mitmproxy 自动解压后存储，看到的就是明文
- **数据留存**：启动时自动清理 7 天前的记录
- **并发安全**：SQLite WAL 模式，mitmdump 写入的同时任意多方只读查询互不阻塞

## 6. 数据库结构

默认路径：`recorder/traffic.db`（已加入 .gitignore）

```
flows 表
┌──────────────┬─────────┬──────────────────────────────────┐
│ 列           │ 类型    │ 说明                             │
├──────────────┼─────────┼──────────────────────────────────┤
│ id           │ INTEGER │ 自增主键                         │
│ ts           │ REAL    │ 请求开始时间（unix 时间戳）      │
│ duration_ms  │ INTEGER │ 请求耗时（毫秒）                 │
│ method       │ TEXT    │ GET / POST / ...                 │
│ scheme       │ TEXT    │ http / https                     │
│ host         │ TEXT    │ 目标域名（查询过滤的主要字段）   │
│ port         │ INTEGER │ 目标端口                         │
│ path         │ TEXT    │ 路径 + query string              │
│ status       │ INTEGER │ HTTP 状态码；连接失败为 NULL     │
│ req_headers  │ TEXT    │ 请求头（JSON）                   │
│ resp_headers │ TEXT    │ 响应头（JSON）                   │
│ req_body     │ TEXT    │ 请求体（截断；二进制为 NULL）    │
│ resp_body    │ TEXT    │ 响应体（截断；二进制为 NULL）    │
│ req_size     │ INTEGER │ 请求体原始字节数                 │
│ resp_size    │ INTEGER │ 响应体原始字节数                 │
│ error        │ TEXT    │ 连接错误信息（无错误为 NULL）    │
└──────────────┴─────────┴──────────────────────────────────┘
索引：idx_flows_host_ts (host, ts)、idx_flows_ts (ts)
```

## 7. 查询与分析

常用查询已整理在 `recorder/queries.sql`，核心模式：

```sql
-- 某域名（含子域名）最近一小时的请求
SELECT id, datetime(ts,'unixepoch','localtime') AS time, method, path, status, duration_ms
FROM flows
WHERE host LIKE '%.baidu.com' AND ts > unixepoch() - 3600
ORDER BY ts DESC;

-- 域名聚合：请求数 / 流量 / 平均耗时 / 错误数
SELECT host, count(*) AS requests, sum(resp_size) AS bytes,
       avg(duration_ms) AS avg_ms,
       sum(status >= 500) AS err_5xx, sum(status >= 400 AND status < 500) AS err_4xx
FROM flows WHERE ts > unixepoch() - 3600
GROUP BY host ORDER BY requests DESC;

-- 失败请求（5xx 或连接错误）
SELECT id, method, host, path, status, error
FROM flows WHERE (status >= 500 OR error IS NOT NULL) AND ts > unixepoch() - 3600;

-- 全文搜索（URL / 请求体 / 响应体）
SELECT id, method, host, path, status FROM flows
WHERE path LIKE '%keyword%' OR req_body LIKE '%keyword%' OR resp_body LIKE '%keyword%';

-- 单条完整详情
SELECT * FROM flows WHERE id = 123;
```

命令行直接执行：

```shell
sqlite3 recorder/traffic.db "SELECT host, count(*) FROM flows GROUP BY host ORDER BY 2 DESC LIMIT 10"
```

## 8. Claude Code 集成

### 默认方式（零配置）

在 Claude Code 会话中直接用自然语言提问，Claude 会用 Bash 执行 sqlite3 查询：

> 最近一小时哪些域名请求最多？
> baidu.com 有没有 5xx？把响应体调出来分析下原因
> 搜一下哪些请求的 body 里有 "token"

### MCP 方式（体验更好，推荐）

注册一次（重启 Claude Code 会话生效）：

```shell
claude mcp add traffic-recorder -- uv run --script /Users/sion/projects/mitmproxy/recorder/mcp_server.py
```

注册后 Claude 可直接调用 4 个结构化工具：

| 工具 | 功能 |
|------|------|
| `list_flows(host, since_seconds, status, limit)` | 列出最近流量，按域名/时间/状态码过滤 |
| `get_flow(flow_id, include_body)` | 取单条完整详情（headers + 可选 body） |
| `domain_stats(since_seconds)` | 域名维度聚合统计 |
| `search_flows(pattern, since_seconds, limit)` | URL/body 全文搜索 |

非默认数据库位置通过环境变量指定：`TRAFFIC_DB=/path/to/traffic.db`。

## 9. 主动告警

`alert_watch.py` 轮询数据库，对新出现的异常请求输出一行事件（200 等正常请求静默）：

```shell
# 所有 5xx 和连接错误
uv run python recorder/alert_watch.py --db recorder/traffic.db

# 关注特定域名：其 4xx 也会告警
uv run python recorder/alert_watch.py --db recorder/traffic.db --host api.example.com

# 关注域名的所有请求都输出（盯接口用）
uv run python recorder/alert_watch.py --db recorder/traffic.db --host api.example.com --all-matching
```

输出示例：

```
[13:39:11] HTTP 500: GET api.example.com/v1/users -> 500 (flow #42)
[13:39:15] connection error: POST dead.example.com/pay -> - error=connection refused (flow #43)
```

在 Claude Code 中可用 Monitor 工具挂上该命令，实现异常流量主动推送到会话。

## 10. 常见问题

**Q: 数据库有 schema 但没有数据？**
多半是流量没走代理。检查 `NO_PROXY` 环境变量（本机默认含 `127.0.0.1`），curl 加 `--noproxy ""`；浏览器/系统代理确认指向 `127.0.0.1:8080`。

**Q: curl 报 `SSL certificate problem`？**
CA 证书未信任。临时用 `--cacert ~/.mitmproxy/mitmproxy-ca-cert.pem`，或按第 2 节安装到系统钥匙串。调试时可临时 `-k`（不要用于正式场景）。

**Q: 查询和写入会互相锁吗？**
不会。SQLite WAL 模式写入者（mitmdump）与只读查询并发安全，已通过 50 并发请求压测验证。

**Q: 数据库会无限变大吗？**
addon 每次启动时清理 7 天前的记录；大 body 已截断到 256KB。

**Q: 想看 WebSocket / TCP 流量？**
当前版本只记录 HTTP(S)。WebSocket 消息可通过扩展 addon 的 `websocket_message` hook 支持，TCP/UDP 流量见 mitmproxy 文档的对应 hook。

**Q: 某个 SDK 的请求完全抓不到（连连接记录都没有）？**
该 SDK 大概率绕过了系统代理（自有 DoH + 直连 socket，广告聚合平台常见）。典型特征：能在抓包里看到它向 `dns.google` 发起的 DoH 域名解析，但后续没有任何到该域名或其 IP 的连接。改用 WireGuard 模式从网络层接管，见第 4.2 节。

**Q: 手机浏览器访问 mitmproxy.it 显示 502？**
本版本的内置证书安装页域名是 `mitm.it`（短域名）。`mitmproxy.it` 会被当作真实网站转发到上游导致 502。手机浏览器应访问 `http://mitm.it`。

## 测试与维护

```shell
uv run pytest recorder/ -q    # 30 个单元测试
uv run ruff check recorder/   # lint
```
