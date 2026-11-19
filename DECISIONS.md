# 架构决策

## 2026-11-19 · 使用 MyGO Native UI

Windows 便携版通过 MyGO v0.10.0 的 `ui.View` 绘制界面。保留 Go 探测、Controller HTTP API 与 WebSocket，以及 Windows named pipe 传输。界面在后台执行网络请求，通过 `Window.Update` 回到 UI 线程更新状态。

MyGO 的 Web 前端模式和 Wails 都需要 WebView 承载界面，因此本次选择 Native UI。原有的应用内部 HTTP 路由随页面一起移除，Mihomo 对外提供的 HTTP API 继续使用。

构建需要 Go 1.27.3 或更高版本。便携配置仍随 exe 存放在 `data/config.json`。新历史保存在 `data/history.json`，旧版 WebView2 历史留在原浏览器存储中。
