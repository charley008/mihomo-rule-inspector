## [2026-11-19 08:43]

### Goal
使用 MyGO Native UI 重建 Windows 桌面界面。

### Findings
Wails 通过进程内 HTTP 路由提供页面数据。探测、Mihomo 通信和日志采集可以直接供 Go 界面调用。

### Actions
重建六个页面，保留便携配置路径，使用 MyGO 文件对话框和剪贴板，移除嵌入的 Web 资源和应用内部 HTTP 路由。

### Modified Files
- `cmd/mihomo-rule-inspector/`：原生窗口、界面状态和页面、无窗口冒烟测试。
- `internal/server/`：提取 Go 服务调用，保留批量重试、规则匹配与日志缓存。
- `go.mod`、`go.sum`、`README.md`：更新依赖与构建说明。
- `web/`：移除原前端资源。

### Result
Windows 原生窗口已启动。模拟 Controller 验证通过。当前机器的默认 HTTP Controller 地址拒绝连接，真实探测未联调。

### Next
使用实际的 HTTP 或 Windows Pipe Controller 配置验证规则命中与批量探测。

## [2026-11-19 08:53]

### Goal
沿用旧版六页的设计，通过 MyGO Native UI 实现。

### Findings
首次迁移采用了顶部导航和简化视图，改变了用户熟悉的信息布局。旧版 Git 源码与用户提供的六张截图明确了布局、样式和表格列。

### Actions
恢复 260 DIP 侧栏、自绘窗口栏、原颜色和卡片样式、历史列表、三张表格、日志行内高亮、规则自动加载和设置网格。

### Modified Files
- `cmd/mihomo-rule-inspector/layout.go`：原生窗口结构、导航、配色与表格样式。
- `cmd/mihomo-rule-inspector/pages.go`、`inspector.go`、`main.go`：恢复六页布局与交互。
- `cmd/mihomo-rule-inspector/native_smoke_test.go`：校验恢复后的页面内容。

### Result
对照了实际 Windows 快速检测窗口和六页 MyGO 离屏渲染。构建、测试和 vet 通过。

### Next
在已启用的 Controller 环境下继续验证业务交互。

## 2026-11-19 · v0.1.3

在原生侧栏底部显示版本号。更新 GitHub Actions 的 Windows 构建命令，并通过 `v0.1.3` 标签触发便携版发布。
