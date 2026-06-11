package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/mihomo"
)

const (
	VerdictDirect  = "DIRECT"
	VerdictProxy   = "PROXY"
	VerdictReject  = "REJECT"
	VerdictUnknown = "UNKNOWN"
)

type ProbeRequest struct {
	Target           string `json:"target"`
	ClearDNSCache    bool   `json:"clearDnsCache"`
	ClearFakeIPCache bool   `json:"clearFakeIpCache"`
	TimeoutMs        int    `json:"timeoutMs"`
}

type BatchProbeRequest struct {
	Targets          []string `json:"targets"`
	ClearDNSCache    bool     `json:"clearDnsCache"`
	ClearFakeIPCache bool     `json:"clearFakeIpCache"`
	TimeoutMs        int      `json:"timeoutMs"`
	Concurrency      int      `json:"concurrency"`
}

type Diagnosis struct {
	Target         string         `json:"target"`
	NormalizedHost string         `json:"normalizedHost"`
	Verdict        string         `json:"verdict"`
	RuleType       string         `json:"ruleType"`
	RulePayload    string         `json:"rulePayload"`
	Policy         string         `json:"policy"`
	FinalProxy     string         `json:"finalProxy"`
	Chains         []string       `json:"chains"`
	Network        string         `json:"network"`
	DstPort        int            `json:"dstPort"`
	DNSResult      map[string]any `json:"dnsResult,omitempty"`
	RawLogs        []string       `json:"rawLogs"`
	RawConnection  map[string]any `json:"rawConnection"`
	DurationMs     int64          `json:"durationMs"`
	Error          string         `json:"error"`
	Suggestions    []string       `json:"suggestions"`
}

type Service struct {
	client *mihomo.Client
	cfg    config.AppConfig
}

func NewService(cfg config.AppConfig) (*Service, error) {
	client, err := mihomo.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Service{client: client, cfg: cfg}, nil
}

func NormalizeTarget(input string) (string, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return "", errors.New("target is required")
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid target: %w", err)
	}

	host := parsed.Hostname()
	if host == "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(strings.Trim(host, "/"))
	if host == "" {
		return "", errors.New("unable to determine host")
	}
	return host, nil
}

func (s *Service) Run(ctx context.Context, req ProbeRequest) (Diagnosis, error) {
	start := time.Now()
	diag := Diagnosis{
		Target:        req.Target,
		Verdict:       VerdictUnknown,
		RawLogs:       []string{},
		RawConnection: map[string]any{},
	}

	host, err := NormalizeTarget(req.Target)
	if err != nil {
		diag.Error = err.Error()
		diag.Suggestions = defaultSuggestions()
		return diag, nil
	}
	diag.NormalizedHost = host

	timeout := req.TimeoutMs
	if timeout <= 0 {
		timeout = s.cfg.TimeoutMs
	}
	if timeout <= 0 {
		timeout = 5000
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout+5000)*time.Millisecond)
	defer cancel()

	if req.ClearDNSCache || s.cfg.ClearDNSCacheBeforeProbe {
		_ = s.client.FlushDNSCache(runCtx)
	}
	if req.ClearFakeIPCache || s.cfg.ClearFakeIPCacheBeforeProbe {
		_ = s.client.FlushFakeIPCache(runCtx)
	}

	evidence := &evidenceStore{}
	logConn, _ := s.client.OpenLogsStream(runCtx, "info")
	connConn, _ := s.client.OpenConnectionsStream(runCtx)
	var wg sync.WaitGroup

	if logConn != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collectLogs(runCtx, logConn, host, evidence)
		}()
	}

	if connConn != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collectConnections(runCtx, connConn, host, evidence)
		}()
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					if snapshot, err := s.client.GetConnections(runCtx); err == nil {
						evidence.ingestSnapshot(host, snapshot)
					}
				}
			}
		}()
	}

	initialConnections, _ := s.client.GetConnections(runCtx)
	evidence.ingestSnapshot(host, initialConnections)

	requestErr := s.runHTTPProbe(runCtx, host, timeout, evidence)
	settleUntil := time.Now().Add(settleWindow(timeout))
	for time.Now().Before(settleUntil) && !evidence.hasEvidence() {
		select {
		case <-runCtx.Done():
			break
		case <-time.After(150 * time.Millisecond):
		}
	}

	finalConnections, _ := s.client.GetConnections(runCtx)
	evidence.ingestSnapshot(host, finalConnections)
	s.closeProbeConnection(evidence)
	cancel()
	if logConn != nil {
		_ = logConn.Close()
	}
	if connConn != nil {
		_ = connConn.Close()
	}
	wg.Wait()

	diag = buildDiagnosis(diag, host, evidence, requestErr)
	diag.DurationMs = time.Since(start).Milliseconds()
	return diag, nil
}

func (s *Service) closeProbeConnection(evidence *evidenceStore) {
	evidence.mu.Lock()
	conn := cloneMap(evidence.connection)
	evidence.mu.Unlock()
	if len(conn) == 0 {
		return
	}

	id := strings.TrimSpace(asString(conn["id"]))
	if id == "" {
		return
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.client.CloseConnection(closeCtx, id)
}

func (s *Service) runHTTPProbe(ctx context.Context, host string, timeoutMs int, evidence *evidenceStore) error {
	proxyURL, err := url.Parse(s.cfg.MixedProxyURL)
	if err != nil {
		return fmt.Errorf("invalid mixed proxy url: %w", err)
	}

	perAttemptTimeout := timeoutMs / 2
	if perAttemptTimeout < 1500 {
		perAttemptTimeout = 1500
	}
	if perAttemptTimeout > 3000 {
		perAttemptTimeout = 3000
	}

	client := &http.Client{
		Timeout: time.Duration(perAttemptTimeout) * time.Millisecond,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			DialContext: (&net.Dialer{Timeout: time.Duration(perAttemptTimeout) * time.Millisecond}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	schemes := []string{"https", "http"}
	var lastErr error
	for _, scheme := range schemes {
		probeURL := fmt.Sprintf("%s://%s/?mihomo_probe=%d", scheme, host, time.Now().UnixMilli())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "mihomo-rule-inspector/1.0")
		req.Header.Set("Cache-Control", "no-cache")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if evidence.hasEvidence() {
				return lastErr
			}
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil
	}

	return lastErr
}

type evidenceStore struct {
	mu         sync.Mutex
	rawLogs    []string
	connection map[string]any
}

func (e *evidenceStore) hasEvidence() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rawLogs) > 0 || len(e.connection) > 0
}

func (e *evidenceStore) addLog(line string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rawLogs = append(e.rawLogs, line)
}

func (e *evidenceStore) setConnection(conn map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.connection = cloneMap(conn)
}

func (e *evidenceStore) ingestSnapshot(host string, snapshot map[string]any) {
	for _, conn := range extractConnectionList(snapshot) {
		if connectionMatchesHost(conn, host) {
			e.setConnection(conn)
		}
	}
}

func collectLogs(ctx context.Context, conn *websocket.Conn, host string, evidence *evidenceStore) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		line := strings.TrimSpace(string(data))
		if line == "" {
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err == nil {
			if message, ok := payload["payload"].(string); ok && containsFold(message, host) {
				evidence.addLog(message)
				continue
			}
		}

		if containsFold(line, host) {
			evidence.addLog(line)
		}
	}
}

func collectConnections(ctx context.Context, conn *websocket.Conn, host string, evidence *evidenceStore) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var snapshot map[string]any
		if err := json.Unmarshal(data, &snapshot); err != nil {
			continue
		}

		for _, item := range extractConnectionList(snapshot) {
			if connectionMatchesHost(item, host) {
				evidence.setConnection(item)
			}
		}
	}
}

func buildDiagnosis(base Diagnosis, host string, evidence *evidenceStore, requestErr error) Diagnosis {
	evidence.mu.Lock()
	rawLogs := append([]string(nil), evidence.rawLogs...)
	connection := cloneMap(evidence.connection)
	evidence.mu.Unlock()

	base.RawLogs = rawLogs
	if connection != nil {
		base.RawConnection = connection
		fillFromConnection(&base, connection)
	}

	if base.Verdict == VerdictUnknown {
		base.Verdict = inferVerdict(base.Chains, base.Policy, base.FinalProxy)
	}

	if requestErr != nil {
		base.Error = requestErr.Error()
	}

	if len(base.RawConnection) == 0 {
		if base.Error == "" {
			base.Error = "本次没有拿到 /connections 证据，检测结果可能不完整，请重试。"
		}
		if len(base.Suggestions) == 0 {
			base.Suggestions = []string{
				"本次只拿到了日志，没有拿到 /connections 数据，所以策略组和最终节点可能不可靠。",
				"建议重试一次；如果仍然为空，请检查 mixed-port、controller、secret，以及是否真的有流量经过 Mihomo。",
			}
		}
	}

	if base.Verdict == VerdictUnknown && len(base.RawLogs) == 0 && len(base.RawConnection) == 0 {
		base.Suggestions = defaultSuggestions()
	} else if base.Error != "" && len(base.Suggestions) == 0 {
		base.Suggestions = []string{
			"即使请求失败，只要 Mihomo 产生连接或日志，结果仍可能有效；请先检查上面的命中证据。",
			"如果证据仍为空，请确认 mixed-port 是否正确，以及目标请求是否真的通过该代理发出。",
		}
	}

	_ = host
	return base
}

func fillFromConnection(diag *Diagnosis, conn map[string]any) {
	metadata := nestedMap(conn, "metadata")
	diag.RuleType = firstString(
		asString(metadata["rule"]),
		asString(conn["rule"]),
	)
	diag.RulePayload = firstString(
		asString(metadata["rulePayload"]),
		asString(conn["rulePayload"]),
	)
	diag.Network = firstString(
		asString(metadata["network"]),
		asString(conn["network"]),
	)
	diag.DstPort = firstInt(
		asInt(metadata["destinationPort"]),
		asInt(conn["dstPort"]),
	)

	chains := extractStringSlice(conn["chains"])
	if len(chains) == 0 {
		chains = extractStringSlice(metadata["chains"])
	}

	diag.Policy = firstString(
		asString(metadata["specialProxy"]),
		lastChain(chains),
	)
	diag.FinalProxy = firstString(
		firstChain(chains),
		asString(conn["outbound"]),
	)
	diag.Chains = normalizeDisplayChains(diag.Policy, diag.FinalProxy, chains)
	diag.Verdict = inferVerdict(chains, diag.Policy, diag.FinalProxy)
}

func inferVerdict(chains []string, policy, finalProxy string) string {
	for _, item := range append([]string{policy, finalProxy}, chains...) {
		switch strings.ToUpper(strings.TrimSpace(item)) {
		case VerdictDirect:
			return VerdictDirect
		case VerdictReject:
			return VerdictReject
		}
	}
	if len(chains) > 0 || finalProxy != "" || policy != "" {
		return VerdictProxy
	}
	return VerdictUnknown
}

func defaultSuggestions() []string {
	return []string{
		"确认 Mihomo 的 mixed-port 配置正确，并且本工具请求确实通过该代理发出。",
		"确认目标域名没有被上游缓存短路，必要时勾选清理 DNS cache 和 fake-ip cache。",
		"确认 Mihomo 已开启 external-controller、secret，并且 log-level 至少为 info。",
		"如果 WebSocket 证据为空，请再次检查 controller 地址和 secret 是否正确。",
	}
}

func extractConnectionList(snapshot map[string]any) []map[string]any {
	if snapshot == nil {
		return nil
	}
	raw, ok := snapshot["connections"]
	if !ok {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if conn, ok := item.(map[string]any); ok {
			out = append(out, conn)
		}
	}
	return out
}

func connectionMatchesHost(conn map[string]any, host string) bool {
	metadata := nestedMap(conn, "metadata")
	fields := []string{
		asString(metadata["host"]),
		asString(metadata["destinationIP"]),
		asString(metadata["destination"]),
		asString(conn["host"]),
		asString(conn["destination"]),
	}
	for _, field := range fields {
		if field != "" && containsFold(field, host) {
			return true
		}
	}
	return false
}

func nestedMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if out, ok := m[key].(map[string]any); ok {
		return out
	}
	return nil
}

func extractStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s := strings.TrimSpace(asString(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func firstInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstChain(chains []string) string {
	if len(chains) == 0 {
		return ""
	}
	return chains[0]
}

func lastChain(chains []string) string {
	if len(chains) == 0 {
		return ""
	}
	return chains[len(chains)-1]
}

func asString(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	case float64:
		return fmt.Sprintf("%.0f", value)
	case int:
		return fmt.Sprintf("%d", value)
	default:
		return ""
	}
}

func asInt(v any) int {
	switch value := v.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		n, _ := value.Int64()
		return int(n)
	case string:
		var out int
		fmt.Sscanf(value, "%d", &out)
		return out
	default:
		return 0
	}
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func settleWindow(timeoutMs int) time.Duration {
	window := time.Duration(timeoutMs/4) * time.Millisecond
	if window < 500*time.Millisecond {
		window = 500 * time.Millisecond
	}
	if window > 1500*time.Millisecond {
		window = 1500 * time.Millisecond
	}
	return window
}
