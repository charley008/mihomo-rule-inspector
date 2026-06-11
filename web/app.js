const state = {
  config: null,
  batchResults: [],
  connections: [],
  logs: [],
  history: [],
  connectionPollTimer: null,
  logsPollTimer: null,
  rulesLoadedOnce: false,
};

const HISTORY_KEY = "mihomo-rule-inspector.history";
const byId = (id) => document.getElementById(id);
const escapeHtml = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");

function switchTab(name) {
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.panel === name);
  });
  if (name === "rules" && !state.rulesLoadedOnce) {
    loadRules().catch((error) => {
      byId("rules-status").textContent = `规则加载失败：${error.message}`;
    });
  }
}

function hasWailsRuntime() {
  return typeof window !== "undefined" && window.runtime;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `HTTP ${response.status}`);
  }
  return response.json();
}

function setQuickLoading(loading) {
  const btn = byId("quick-probe-btn");
  const progress = byId("quick-progress");
  const bar = byId("quick-progress-bar");
  btn.disabled = loading;
  btn.textContent = loading ? "检测中..." : "开始检测";
  progress.hidden = !loading;
  bar.hidden = !loading;
}

function renderQuickResult(result) {
  const wrap = byId("quick-result");
  wrap.innerHTML = "";
  const tpl = byId("result-template");
  const node = tpl.content.firstElementChild.cloneNode(true);
  node.classList.add((result.verdict || "unknown").toLowerCase());
  node.querySelector(".result-title").textContent = result.target || "未提供目标";
  node.querySelector(".result-host").textContent = result.normalizedHost || "-";
  node.querySelector(".verdict").textContent = result.verdict || "UNKNOWN";
  node.querySelector(".verdict").classList.add((result.verdict || "unknown").toLowerCase());
  node.querySelector(".rule-type").textContent = result.ruleType || "-";
  node.querySelector(".rule-payload").textContent = result.rulePayload || "-";
  node.querySelector(".policy").textContent = result.policy || "-";
  node.querySelector(".final-proxy").textContent = result.finalProxy || "-";
  node.querySelector(".chains").textContent = formatChains(result.chains);
  node.querySelector(".network").textContent = result.network || "-";
  node.querySelector(".dst-port").textContent = result.dstPort || "-";
  node.querySelector(".duration").textContent = `${result.durationMs || 0} ms`;
  node.querySelector(".raw-output").textContent = JSON.stringify(
    {
      rawLogs: result.rawLogs || [],
      rawConnection: result.rawConnection || {},
      dnsResult: result.dnsResult || null,
      error: result.error || "",
    },
    null,
    2,
  );

  const suggestions = node.querySelector(".suggestions");
  if (result.error) {
    suggestions.insertAdjacentHTML(
      "beforeend",
      `<div class="hint error">${escapeHtml(result.error)}</div>`,
    );
  }
  (result.suggestions || []).forEach((item) => {
    suggestions.insertAdjacentHTML("beforeend", `<div class="hint">${escapeHtml(item)}</div>`);
  });
  wrap.appendChild(node);
}

function renderBatchResults() {
  const tbody = byId("batch-table").querySelector("tbody");
  tbody.innerHTML = "";
  state.batchResults.forEach((item) => {
    const ruleText = formatRuleLabel(item.ruleType, item.rulePayload);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(item.normalizedHost || item.target || "-")}</td>
      <td><span class="badge ${(item.verdict || "unknown").toLowerCase()}">${escapeHtml(item.verdict || "UNKNOWN")}</span></td>
      <td>${escapeHtml(ruleText)}</td>
      <td>${escapeHtml(item.policy || "-")}</td>
      <td>${escapeHtml(item.finalProxy || "-")}</td>
      <td>${escapeHtml(item.durationMs || 0)} ms</td>
      <td>${escapeHtml(item.error || "")}</td>
    `;
    tbody.appendChild(tr);
  });
}

function normalizeConnectionRows(payload) {
  return Array.isArray(payload?.connections) ? payload.connections : [];
}

function renderConnections() {
  const tbody = byId("connections-table").querySelector("tbody");
  const keyword = byId("connections-filter").value.trim().toLowerCase();
  tbody.innerHTML = "";

  state.connections
    .filter((item) => {
      if (!keyword) return true;
      const host = String(item?.metadata?.host || item?.host || "").toLowerCase();
      return host.includes(keyword);
    })
    .sort((a, b) => getConnectionTimestamp(b) - getConnectionTimestamp(a))
    .forEach((item) => {
      const metadata = item.metadata || {};
      const rawChains = Array.isArray(item.chains)
        ? item.chains
        : Array.isArray(metadata.chains)
          ? metadata.chains
          : [];
      const displayChains = normalizeDisplayChains(
        metadata.specialProxy || "",
        item.outbound || rawChains[0] || "",
        rawChains,
      );
      const destination = formatDestination(metadata, item);
      const ruleText = formatRule(metadata, item);
      const typeText = formatConnectionType(metadata, item);
      const hostText = formatHost(metadata, item);
      const downloadSpeed = metadata.downloadSpeed ?? item.downloadSpeed ?? item.down ?? 0;
      const uploadSpeed = metadata.uploadSpeed ?? item.uploadSpeed ?? item.up ?? 0;

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(hostText)}</td>
        <td>${escapeHtml(formatBytes(item.download || 0))}</td>
        <td>${escapeHtml(formatBytes(item.upload || 0))}</td>
        <td>${escapeHtml(formatSpeed(downloadSpeed))}</td>
        <td>${escapeHtml(formatSpeed(uploadSpeed))}</td>
        <td>${escapeHtml(formatChains(displayChains))}</td>
        <td>${escapeHtml(ruleText)}</td>
        <td>${escapeHtml(formatRelativeTime(item.start))}</td>
        <td>${escapeHtml(destination)}</td>
        <td>${escapeHtml(typeText)}</td>
      `;
      tbody.appendChild(tr);
    });
}

function getConnectionTimestamp(item) {
  const raw = item?.start;
  if (!raw) return 0;
  const ts = new Date(raw).getTime();
  return Number.isNaN(ts) ? 0 : ts;
}

function formatChains(chains) {
  return Array.isArray(chains) && chains.length ? chains.join(" / ") : "-";
}

function formatRuleLabel(ruleType, rulePayload) {
  const type = String(ruleType || "").trim().replace(/^[-\s]+/, "");
  const payload = String(rulePayload || "").trim().replace(/^[-\s]+/, "");
  if (type && payload) {
    return `${type}(${payload})`;
  }
  return type || payload || "-";
}

function normalizeDisplayChains(policy, finalProxy, rawChains = []) {
  const display = [];
  const add = (value) => {
    value = String(value || "").trim();
    if (!value) return;
    if (display.some((item) => item.toLowerCase() === value.toLowerCase())) return;
    display.push(value);
  };

  add(policy);
  [...rawChains].reverse().forEach(add);
  add(finalProxy);
  return display;
}

function formatDestination(metadata, item) {
  const port = metadata.destinationPort || item.dstPort || "";
  const destinationIP =
    metadata.destinationIP ||
    metadata.remoteDestination ||
    item.destinationIP ||
    item.destination ||
    "";

  if (destinationIP && port) {
    return `${destinationIP}:${port}`;
  }
  if (destinationIP) {
    return destinationIP;
  }
  return destinationIP || "-";
}

function formatHost(metadata, item) {
  const host = String(metadata.host || item.host || "").trim();
  const port = metadata.destinationPort || item.dstPort || "";
  if (host && port) {
    return `${host}:${port}`;
  }
  return host || "-";
}

function formatRule(metadata, item) {
  const rule = String(metadata.rule || item.rule || "").trim();
  const payload = String(metadata.rulePayload || item.rulePayload || "").trim();
  if (rule && payload) {
    return `${rule}(${payload})`;
  }
  return rule || payload || "-";
}

function formatConnectionType(metadata, item) {
  const network = String(metadata.network || item.network || "").trim().toLowerCase();
  const type = String(metadata.type || item.type || "").trim();
  if (type) return type;
  if (!network) return "-";
  return network === "tcp" ? "HTTPS(tcp)" : network.toUpperCase();
}

function formatBytes(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num) || num <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = num;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const digits = size >= 100 || unitIndex === 0 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${units[unitIndex]}`;
}

function formatSpeed(value) {
  return `${formatBytes(value)}/s`;
}

function formatRelativeTime(value) {
  if (!value) return "-";
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) {
    return String(value);
  }
  const diffMs = Date.now() - timestamp.getTime();
  if (diffMs < 0) return "刚刚";
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 10) return "刚刚";
  if (diffSec < 60) return `${diffSec} 秒前`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} 分钟前`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour} 小时前`;
  const diffDay = Math.floor(diffHour / 24);
  if (diffDay < 30) return `${diffDay} 天前`;
  return timestamp.toLocaleString();
}

function renderLogs() {
  const container = byId("logs-view");
  const keyword = byId("logs-filter").value.trim().toLowerCase();
  const filtered = state.logs.filter((line) => !keyword || line.toLowerCase().includes(keyword));
  const html = filtered
    .slice(-300)
    .map((line) => highlightLog(line))
    .join("<br />");
  container.innerHTML = html || '<div class="muted">暂无日志</div>';
  container.scrollTop = container.scrollHeight;
}

function highlightLog(line) {
  return escapeHtml(line).replaceAll(
    /(match|using|DIRECT|REJECT|proxy|rule)/gi,
    "<mark>$1</mark>",
  );
}

function renderControllerInfo(controller) {
  if (!controller) {
    byId("cfg-controller-active").textContent = "-";
    return;
  }
  byId("cfg-controller-active").textContent =
    controller.displayName || controller.baseUrl || controller.pipeName || "-";
}

function formatAttempts(attempts = []) {
  if (!attempts.length) {
    return "未返回探测轨迹。";
  }
  return attempts
    .map((attempt, index) => {
      const status = attempt.success ? "成功" : "失败";
      const secret = attempt.secretSource ? `secret=${attempt.secretSource}` : "secret=-";
      return `${index + 1}. [${attempt.kind}] ${attempt.target} ${secret} ${status}${attempt.message ? ` | ${attempt.message}` : ""}`;
    })
    .join("\n");
}

function loadHistory() {
  try {
    state.history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    state.history = [];
  }
}

function saveHistory() {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
}

function addHistory(result) {
  const item = {
    target: result.target,
    normalizedHost: result.normalizedHost,
    verdict: result.verdict,
    ruleType: result.ruleType,
    rulePayload: result.rulePayload,
    policy: result.policy,
    finalProxy: result.finalProxy,
    chains: result.chains || [],
    durationMs: result.durationMs,
    error: result.error || "",
    rawLogs: result.rawLogs || [],
    rawConnection: result.rawConnection || {},
    dnsResult: result.dnsResult || null,
    suggestions: result.suggestions || [],
    createdAt: new Date().toISOString(),
  };
  state.history = [item, ...state.history].slice(0, 20);
  saveHistory();
  renderHistory();
}

function renderHistory() {
  const wrap = byId("history-list");
  wrap.innerHTML = "";
  if (!state.history.length) {
    wrap.innerHTML = '<div class="muted">暂无历史记录</div>';
    return;
  }

  state.history.forEach((item, index) => {
    const button = document.createElement("button");
    button.className = "history-item";
    button.innerHTML = `
      <div class="history-main">
        <strong>${escapeHtml(item.normalizedHost || item.target || "-")}</strong>
        <span class="badge ${(item.verdict || "unknown").toLowerCase()}">${escapeHtml(item.verdict || "UNKNOWN")}</span>
      </div>
      <div class="history-meta">
        <span>${escapeHtml(item.ruleType || "-")} ${escapeHtml(item.rulePayload || "")}</span>
        <span>${escapeHtml(item.policy || "-")} / ${escapeHtml(item.finalProxy || "-")}</span>
        <span>${escapeHtml(item.durationMs || 0)} ms</span>
      </div>
    `;
    button.addEventListener("click", () => {
      byId("quick-target").value = item.target || item.normalizedHost || "";
      renderQuickResult(item);
      switchTab("quick");
    });
    wrap.appendChild(button);
    if (index < state.history.length - 1) {
      wrap.appendChild(document.createElement("hr"));
    }
  });
}

async function loadConfig() {
  state.config = await api("/api/config");
  byId("cfg-controller-mode").value = state.config.controllerMode || "auto";
  byId("cfg-controller").value = state.config.controllerUrl || "";
  byId("cfg-controller-pipe").value = state.config.controllerPipe || "";
  byId("cfg-secret").value = state.config.secret || "";
  byId("cfg-mixed").value = state.config.mixedProxyUrl || "";
  byId("cfg-listen").value = state.config.listenAddr || "";
  byId("cfg-timeout").value = state.config.timeoutMs || 5000;
  byId("cfg-clear-dns").checked = !!state.config.clearDnsCacheBeforeProbe;
  byId("cfg-clear-fakeip").checked = !!state.config.clearFakeIpCacheBeforeProbe;
  byId("cfg-path").textContent = state.config.configPath || "-";

  byId("quick-timeout").value = state.config.timeoutMs || 5000;
  byId("quick-clear-dns").checked = !!state.config.clearDnsCacheBeforeProbe;
  byId("quick-clear-fakeip").checked = !!state.config.clearFakeIpCacheBeforeProbe;
}

async function saveConfig() {
  const payload = {
    controllerMode: byId("cfg-controller-mode").value,
    controllerUrl: byId("cfg-controller").value.trim(),
    controllerPipe: byId("cfg-controller-pipe").value.trim(),
    secret: byId("cfg-secret").value,
    mixedProxyUrl: byId("cfg-mixed").value.trim(),
    listenAddr: byId("cfg-listen").value.trim(),
    timeoutMs: Number(byId("cfg-timeout").value || 5000),
    clearDnsCacheBeforeProbe: byId("cfg-clear-dns").checked,
    clearFakeIpCacheBeforeProbe: byId("cfg-clear-fakeip").checked,
  };

  state.config = await api("/api/config", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  byId("cfg-path").textContent = state.config.configPath || "-";
  const saveResult = byId("save-result");
  saveResult.hidden = false;
  saveResult.textContent = `配置已保存：${new Date().toLocaleTimeString()}`;
}

async function testHealth() {
  const result = await api("/api/health");
  renderControllerInfo(result.controller);
  const summary = result.ok
    ? `连接成功。\nController: ${result.controller?.displayName || "-"}`
    : `连接失败。\n${result.error || JSON.stringify(result.errors || {})}`;
  byId("health-result").textContent = `${summary}\n\n探测轨迹：\n${formatAttempts(result.attempts)}`;
}

async function quickProbe() {
  setQuickLoading(true);
  try {
    const payload = {
      target: byId("quick-target").value.trim(),
      clearDnsCache: byId("quick-clear-dns").checked,
      clearFakeIpCache: byId("quick-clear-fakeip").checked,
      timeoutMs: Number(byId("quick-timeout").value || 5000),
    };
    const result = await api("/api/probe", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderQuickResult(result);
    addHistory(result);
  } finally {
    setQuickLoading(false);
  }
}

async function batchProbe() {
  const targets = byId("batch-targets")
    .value.split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);

  const result = await api("/api/batch-probe", {
    method: "POST",
    body: JSON.stringify({
      targets,
      clearDnsCache: byId("quick-clear-dns").checked,
      clearFakeIpCache: byId("quick-clear-fakeip").checked,
      timeoutMs: Number(byId("quick-timeout").value || 5000),
      concurrency: 1,
    }),
  });

  state.batchResults = result.results || [];
  renderBatchResults();
}

function copyBatchResults() {
  navigator.clipboard.writeText(JSON.stringify(state.batchResults, null, 2));
}

function exportBatchResults() {
  const blob = new Blob([JSON.stringify(state.batchResults, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "batch-results.json";
  a.click();
  URL.revokeObjectURL(url);
}

async function refreshConnections() {
  try {
    const snapshot = await api("/api/connections");
    state.connections = normalizeConnectionRows(snapshot);
    renderConnections();
    byId("connections-status").textContent =
      `自动刷新中，最近更新：${new Date().toLocaleTimeString()}，当前 ${state.connections.length} 条连接`;
  } catch (error) {
    byId("connections-status").textContent = `连接列表刷新失败：${error.message}`;
  }
}

async function refreshLogs() {
  try {
    const snapshot = await api("/api/logs?limit=300");
    state.logs = Array.isArray(snapshot.logs) ? snapshot.logs : [];
    renderLogs();
  } catch (error) {
    state.logs = [...state.logs.slice(-299), `error: ${error.message}`];
    renderLogs();
  }
}

async function loadRules() {
  const target = byId("rules-target").value.trim();
  const status = byId("rules-status");
  status.textContent = "正在加载规则...";

  try {
    const result = await api(`/api/rules?target=${encodeURIComponent(target)}`);
    const tbody = byId("rules-table").querySelector("tbody");
    const candidatesWrap = byId("rules-candidates");
    tbody.innerHTML = "";
    candidatesWrap.innerHTML = "";

    const candidateIndexes = new Map((result.candidates || []).map((item) => [item.index, item]));
    (result.candidates || []).forEach((item) => {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = `#${item.index} ${item.type} ${item.payload || ""} (${item.matchType})`;
      candidatesWrap.appendChild(chip);
    });

    const rules = Array.isArray(result.rules?.rules)
      ? result.rules.rules
      : Array.isArray(result.rules)
        ? result.rules
        : [];

    rules.forEach((rule, index) => {
      const tr = document.createElement("tr");
      const candidate = candidateIndexes.get(index);
      tr.innerHTML = `
        <td>${index}</td>
        <td>${escapeHtml(rule.type || "-")}</td>
        <td>${escapeHtml(rule.payload || "-")}</td>
        <td>${escapeHtml(rule.proxy || rule.adapter || "-")}</td>
        <td>${escapeHtml(candidate?.matchType || "")}</td>
      `;
      tbody.appendChild(tr);
    });

    status.textContent =
      `规则加载完成：${rules.length} 条规则，${(result.candidates || []).length} 条候选匹配` +
      `${result.rulesError || result.providerError ? `，rulesError=${result.rulesError || "-"} providerError=${result.providerError || "-"}` : ""}`;
    state.rulesLoadedOnce = true;
  } catch (error) {
    state.rulesLoadedOnce = false;
    status.textContent = `规则加载失败：${error.message}`;
  }
}

function startConnectionsPolling() {
  if (state.connectionPollTimer) {
    clearInterval(state.connectionPollTimer);
  }
  state.connectionPollTimer = setInterval(() => {
    refreshConnections().catch(() => {});
  }, 1000);
}

function startLogsPolling() {
  if (state.logsPollTimer) {
    clearInterval(state.logsPollTimer);
  }
  state.logsPollTimer = setInterval(() => {
    refreshLogs().catch(() => {});
  }, 1000);
}

function bindEvents() {
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  byId("cfg-save-btn").addEventListener("click", saveConfig);
  byId("cfg-test-btn").addEventListener("click", testHealth);
  byId("quick-probe-btn").addEventListener("click", quickProbe);
  byId("batch-probe-btn").addEventListener("click", batchProbe);
  byId("batch-copy-btn").addEventListener("click", copyBatchResults);
  byId("batch-export-btn").addEventListener("click", exportBatchResults);
  byId("connections-refresh-btn").addEventListener("click", refreshConnections);
  byId("connections-filter").addEventListener("input", renderConnections);
  byId("logs-filter").addEventListener("input", renderLogs);
  byId("logs-clear-btn").addEventListener("click", () => {
    state.logs = [];
    renderLogs();
  });
  byId("rules-load-btn").addEventListener("click", loadRules);
  byId("history-clear-btn").addEventListener("click", () => {
    state.history = [];
    saveHistory();
    renderHistory();
  });

  const minBtn = byId("window-min-btn");
  const maxBtn = byId("window-max-btn");
  const closeBtn = byId("window-close-btn");
  if (minBtn) {
    minBtn.addEventListener("click", () => {
      if (hasWailsRuntime()) window.runtime.WindowMinimise();
    });
  }
  if (maxBtn) {
    maxBtn.addEventListener("click", () => {
      if (hasWailsRuntime()) window.runtime.WindowToggleMaximise();
    });
  }
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      if (hasWailsRuntime()) {
        window.runtime.Quit();
      } else {
        window.close();
      }
    });
  }
}

async function init() {
  bindEvents();
  loadHistory();
  renderHistory();
  await loadConfig();
  await refreshConnections().catch(() => {});
  await refreshLogs().catch(() => {});
  startConnectionsPolling();
  startLogsPolling();
}

init().catch((error) => {
  console.error(error);
  byId("health-result").textContent = error.message;
});
