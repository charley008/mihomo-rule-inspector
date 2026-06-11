# mihomo-rule-inspector

`mihomo-rule-inspector` 是一个用 Go 编写的本地桌面诊断工具，用来确认某个域名在 `mihomo` Meta 内核里实际命中了哪条规则、哪个策略组、最终走哪个节点。

它不依赖 Node.js、Electron 或外部 `curl`。当前版本定位为 Windows 64 位便携桌面工具，界面使用 Wails 承载，前端仍然是普通 HTML/CSS/JavaScript，并通过 `go:embed` 内嵌进单个 Go 可执行文件。

## 功能简介

- 输入域名、URL 或 IP，主动通过 Mihomo `mixed-port` 发起探测
- 同时监听 `/logs` 与 `/connections`，尽量还原真实命中规则
- 结构化展示最终结论：`DIRECT / PROXY / REJECT / UNKNOWN`
- 展示命中规则、规则载荷、策略组、最终节点、链路、连接信息
- 支持批量检测、规则弱匹配浏览、实时连接、日志辅助查看
- 支持 Windows 下 Clash Verge Dev/Rev 的 `external-controller-pipe`

## 实现原理

工具的核心思路不是只高亮日志，而是做一次“主动探测 + 证据归并”：

1. 归一化用户输入，提取目标 host
2. 通过 Mihomo controller 查询配置、规则、连接和日志
3. 使用 Go 原生 `net/http` 强制走 `mixed-port` 发起探测请求
4. 在探测窗口内同时收集 `/connections` 和 `/logs?level=info`
5. 优先使用 `/connections` 中的 `rule / rulePayload / chains`
6. 如果连接里没有完整证据，再回退解析日志文本
7. 返回结构化诊断结果，供前端卡片和表格展示

## 技术栈

- 后端：Go 1.23+
- 桌面壳：Wails v2
- 前端：原生 HTML / CSS / JavaScript
- Mihomo 通信：HTTP API + WebSocket
- Windows Pipe：`github.com/Microsoft/go-winio`
- 图标资源：Go 生成 `.ico`，并通过 Windows 资源文件编入 exe

## 目录约定

源码和运行产物分开：

- `cmd/`、`internal/`、`web/`：源码
- `dist/`：编译输出目录
- `dist/data/`：便携模式运行数据目录，可放 `config.json`

推荐结构：

```text
mihomo-rule-inspector/
  cmd/
  internal/
  web/
  dist/
    mihomo-rule-inspector.exe
    data/
      config.json
```

## 配置文件位置

程序只使用可执行文件目录下的：

- `data/config.json`

同时会在同目录生成一份示例说明：

- `data/config.example.json`

示例：

```text
dist/
  mihomo-rule-inspector.exe
  data/
    config.json
    config.example.json
```

其中：

- `config.json`：程序真正读取的配置文件，不带注释字段
- `config.example.json`：带中文说明的示例文件，给用户参考

这样源码目录和运行配置始终分离，打包也更直接。

## Controller 模式

工具支持三种 controller 模式：

- `auto`
- `http`
- `windows_pipe`

`auto` 模式下会优先尝试 HTTP controller：

- `http://127.0.0.1:9097`
- `http://127.0.0.1:9090`
- `http://127.0.0.1:9091-9100`

如果 HTTP 全部失败，并且当前系统是 Windows，则继续尝试：

- `\\.\pipe\verge-mihomo`

这可以兼容 Clash Verge Dev/Rev 常见的运行时配置：

```yaml
external-controller-pipe: \\.\pipe\verge-mihomo
```

注意：

- named pipe 只用于 controller API
- 实际探测流量仍然必须通过 `mixed-port`

## 特性

- 单执行文件运行，启动后直接弹出桌面窗口
- 后端直接请求 Mihomo controller API，避免浏览器 CORS 问题
- 使用 Go 原生 `net/http`，强制经由 Mihomo `mixed-port` 发起探测
- 优先读取 `/connections` 的 `rule`、`rulePayload`、`chains`
- `/connections` 没有结果时，再回退到 `/logs?level=info` 做宽松解析
- 批量检测、实时连接、日志辅助、规则弱匹配浏览
- 设置页直接显示当前实际使用的 `config.json` 路径

## 依赖

- Go 1.23+
- Mihomo Meta 分支内核
- Windows 下建议安装 Microsoft WebView2 Runtime

## Mihomo 配置要求

请确认 Mihomo 已开启以下配置：

- `external-controller`
- `secret`
- `mixed-port`
- `log-level: info`

可选但推荐：

- `external-controller-cors`

示例：

```yaml
external-controller: 127.0.0.1:9090
secret: your-secret
mixed-port: 10801
log-level: info
external-controller-cors:
  allow-origins:
    - "*"
  allow-private-network: true
```

## 构建

推荐直接输出到 `dist/`：

```bash
go build -tags desktop,production -ldflags="-w -s -H windowsgui" -o dist/mihomo-rule-inspector.exe ./cmd/mihomo-rule-inspector
```

Linux/macOS：

```bash
go build -tags desktop,production -ldflags="-w -s" -o dist/mihomo-rule-inspector ./cmd/mihomo-rule-inspector
```

如果你想在 Windows 下隐藏控制台窗口，可以使用：

```powershell
go build -tags desktop,production -ldflags="-w -s -H windowsgui" -o dist\mihomo-rule-inspector.exe ./cmd/mihomo-rule-inspector
```

对于 Wails 桌面版，Windows 构建请始终保留：

- `-tags desktop,production`

否则运行时会出现 “Wails applications will not build without the correct build tags” 报错。

## 发布

仓库内置了 GitHub Actions 工作流：

- 当推送 `v*` 形式的 tag，例如 `v0.1.0`
- 会自动在 `windows-latest` 上编译 `Windows x64`
- 并把 `mihomo-rule-inspector.exe` 打包到 GitHub Release

如果你想要便携模式，先创建 `dist/data/`：

```bash
mkdir -p dist/data
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force dist\data | Out-Null
```

## 运行

```bash
./dist/mihomo-rule-inspector.exe
```

启动后会直接打开桌面窗口。

说明：

- `listenAddr` 目前作为兼容模式保留字段保存在配置中
- 当前桌面窗口模式下，通常不需要手动访问浏览器地址

## 页面说明

### 快速检测

- 输入域名、URL 或 IP
- 自动归一化为 host
- 通过 Mihomo `mixed-port` 主动发起：
  - `https://host/?mihomo_probe=<timestamp>`
  - 失败后回退 `http://host/?mihomo_probe=<timestamp>`
- 收集 3 到 5 秒内相关的 logs 和 connections

### 批量检测

- 一行一个目标
- 默认串行执行，避免并发过高影响判断
- 支持复制结果和导出 JSON

### 实时连接

- 查看当前 `/connections`
- 支持按 host 过滤

### 日志

- 订阅 `/logs?level=info`
- 高亮 `match`、`using`、`DIRECT`、`REJECT`、`proxy`、`rule`

### 规则浏览

- 调用 `/rules` 和 `/providers/rules`
- 对 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`DOMAIN-REGEX`、`MATCH` 做弱匹配提示
- 最终实际命中结果仍以 `/connections` 和 `/logs` 为准

## 后端 API

- `GET /api/config`
- `POST /api/config`
- `GET /api/health`
- `POST /api/probe`
- `POST /api/batch-probe`
- `GET /api/rules`
- `GET /api/connections`
- `GET /api/logs`
- `GET /api/logs/ws`
- `GET /api/connections/ws`

## 说明

- Secret 不会写死在源码中。
- 如果目标站请求失败，只要 Mihomo 产生了连接或日志，工具仍会尽量给出规则判断。
- 如果没有拿到证据，页面会提示排查方向：`mixed-port`、controller secret、缓存、`log-level` 等。
