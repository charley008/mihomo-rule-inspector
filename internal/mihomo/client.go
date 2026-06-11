package mihomo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"mihomo-rule-inspector/internal/config"
)

const pipeBaseURL = "http://mihomo.pipe"

type ControllerInfo struct {
	ConfiguredMode string `json:"configuredMode"`
	Mode           string `json:"mode"`
	BaseURL        string `json:"baseUrl"`
	PipeName       string `json:"pipeName"`
	DisplayName    string `json:"displayName"`
	SupportsWS     bool   `json:"supportsWebSocket"`
	SecretSource   string `json:"secretSource"`
}

type ControllerAttempt struct {
	Kind         string `json:"kind"`
	Target       string `json:"target"`
	SecretSource string `json:"secretSource"`
	Success      bool   `json:"success"`
	Message      string `json:"message"`
}

type ControllerDetection struct {
	Info     ControllerInfo      `json:"info"`
	Attempts []ControllerAttempt `json:"attempts"`
}

type Client struct {
	baseURL    *url.URL
	secret     string
	httpClient *http.Client
	info       ControllerInfo
	netDial    dialContextFunc
	attempts   []ControllerAttempt
}

type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type resolvedController struct {
	baseURL    *url.URL
	secret     string
	httpClient *http.Client
	info       ControllerInfo
	netDial    dialContextFunc
	attempts   []ControllerAttempt
}

type secretCandidate struct {
	value  string
	source string
}

func NewClient(cfg config.AppConfig) (*Client, error) {
	resolved, err := resolveController(cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		baseURL:    resolved.baseURL,
		secret:     resolved.secret,
		httpClient: resolved.httpClient,
		info:       resolved.info,
		netDial:    resolved.netDial,
		attempts:   append([]ControllerAttempt(nil), resolved.attempts...),
	}, nil
}

func DetectController(cfg config.AppConfig) (ControllerDetection, error) {
	resolved, err := resolveController(cfg)
	if err != nil {
		return ControllerDetection{}, err
	}
	return ControllerDetection{
		Info:     resolved.info,
		Attempts: append([]ControllerAttempt(nil), resolved.attempts...),
	}, nil
}

func (c *Client) Info() ControllerInfo {
	return c.info
}

func (c *Client) Attempts() []ControllerAttempt {
	return append([]ControllerAttempt(nil), c.attempts...)
}

func (c *Client) GetVersion(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, "/version", nil)
}

func (c *Client) GetConfigs(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, "/configs", nil)
}

func (c *Client) GetRules(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, "/rules", nil)
}

func (c *Client) GetRuleProviders(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, "/providers/rules", nil)
}

func (c *Client) GetConnections(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, "/connections", nil)
}

func (c *Client) QueryDNS(ctx context.Context, name, recordType string) (map[string]any, error) {
	values := url.Values{}
	values.Set("name", name)
	values.Set("type", recordType)
	return c.getJSON(ctx, "/dns/query", values)
}

func (c *Client) FlushDNSCache(ctx context.Context) error {
	return c.postEmpty(ctx, "/cache/dns/flush")
}

func (c *Client) FlushFakeIPCache(ctx context.Context) error {
	return c.postEmpty(ctx, "/cache/fakeip/flush")
}

func (c *Client) OpenLogsStream(ctx context.Context, level string) (*websocket.Conn, error) {
	values := url.Values{}
	values.Set("level", level)
	return c.openWS(ctx, "/logs", values)
}

func (c *Client) OpenConnectionsStream(ctx context.Context) (*websocket.Conn, error) {
	values := url.Values{}
	values.Set("interval", "1000")
	return c.openWS(ctx, "/connections", values)
}

func (c *Client) getJSON(ctx context.Context, path string, values url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.resolve(path, values), nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req.Header)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := expectOK(resp); err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) postEmpty(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.resolve(path, nil), nil)
	if err != nil {
		return err
	}
	c.applyAuth(req.Header)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return expectOK(resp)
}

func (c *Client) openWS(ctx context.Context, path string, values url.Values) (*websocket.Conn, error) {
	wsURL := *c.baseURL
	if wsURL.Scheme == "https" {
		wsURL.Scheme = "wss"
	} else {
		wsURL.Scheme = "ws"
	}
	wsURL.Path = strings.TrimRight(wsURL.Path, "/") + path
	if values == nil {
		values = url.Values{}
	}
	if c.secret != "" {
		values.Set("token", c.secret)
	}
	wsURL.RawQuery = values.Encode()

	header := http.Header{}
	c.applyAuth(header)
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	if c.netDial != nil {
		dialer.NetDialContext = c.netDial
	}

	conn, resp, err := dialer.DialContext(ctx, wsURL.String(), header)
	if err != nil && resp != nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("websocket dial failed: %v (%s)", err, strings.TrimSpace(string(body)))
	}
	return conn, err
}

func (c *Client) resolve(path string, values url.Values) string {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + path
	if values != nil {
		u.RawQuery = values.Encode()
	}
	return u.String()
}

func (c *Client) applyAuth(header http.Header) {
	if c.secret != "" {
		header.Set("Authorization", "Bearer "+c.secret)
	}
}

func resolveController(cfg config.AppConfig) (*resolvedController, error) {
	mode := strings.TrimSpace(cfg.ControllerMode)
	if mode == "" {
		mode = config.ControllerModeAuto
	}

	secrets := buildSecretCandidates(cfg.Secret)
	allAttempts := make([]ControllerAttempt, 0, 24)

	if mode == config.ControllerModeAuto || mode == config.ControllerModeHTTP {
		resolved, err := tryHTTPControllers(cfg, mode, secrets)
		allAttempts = append(allAttempts, resolvedAttempts(resolved)...)
		if err == nil {
			resolved.attempts = allAttempts
			return resolved, nil
		}
		if mode == config.ControllerModeHTTP {
			return nil, err
		}
	}

	if mode == config.ControllerModeAuto || mode == config.ControllerModeWindowsPipe {
		resolved, err := tryPipeController(cfg, mode, secrets)
		allAttempts = append(allAttempts, resolvedAttempts(resolved)...)
		if err == nil {
			resolved.attempts = allAttempts
			return resolved, nil
		}
		if mode == config.ControllerModeWindowsPipe {
			return nil, err
		}
	}

	return nil, fmt.Errorf("unable to connect to Mihomo controller in %s mode", mode)
}

func tryHTTPControllers(cfg config.AppConfig, mode string, secrets []secretCandidate) (*resolvedController, error) {
	var errs []string
	attempts := make([]ControllerAttempt, 0, 24)

	for _, rawURL := range httpCandidates(cfg.ControllerURL, mode == config.ControllerModeAuto) {
		baseURL, err := url.Parse(strings.TrimRight(rawURL, "/"))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rawURL, err))
			attempts = append(attempts, ControllerAttempt{
				Kind:    config.ControllerModeHTTP,
				Target:  rawURL,
				Success: false,
				Message: err.Error(),
			})
			continue
		}

		client := &http.Client{Timeout: 4 * time.Second}
		for _, secret := range secrets {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			err = probeVersion(ctx, client, baseURL, secret.value)
			cancel()

			attempt := ControllerAttempt{
				Kind:         config.ControllerModeHTTP,
				Target:       baseURL.String(),
				SecretSource: secret.source,
				Success:      err == nil,
			}
			if err == nil {
				attempt.Message = "GET /version succeeded"
				attempts = append(attempts, attempt)
				return &resolvedController{
					baseURL:    baseURL,
					secret:     secret.value,
					httpClient: &http.Client{Timeout: 15 * time.Second},
					info: ControllerInfo{
						ConfiguredMode: mode,
						Mode:           config.ControllerModeHTTP,
						BaseURL:        baseURL.String(),
						DisplayName:    "HTTP Controller " + baseURL.String(),
						SupportsWS:     true,
						SecretSource:   secret.source,
					},
					attempts: attempts,
				}, nil
			}

			attempt.Message = err.Error()
			attempts = append(attempts, attempt)
			errs = append(errs, fmt.Sprintf("%s [%s]: %v", baseURL.String(), secret.source, err))
		}
	}

	return &resolvedController{attempts: attempts}, fmt.Errorf("http controller unavailable: %s", strings.Join(errs, "; "))
}

func tryPipeController(cfg config.AppConfig, mode string, secrets []secretCandidate) (*resolvedController, error) {
	pipeName := strings.TrimSpace(cfg.ControllerPipe)
	if pipeName == "" {
		pipeName = config.DefaultControllerPipe
	}

	if runtime.GOOS != "windows" {
		return &resolvedController{attempts: []ControllerAttempt{{
			Kind:    config.ControllerModeWindowsPipe,
			Target:  pipeName,
			Success: false,
			Message: "windows pipe controller is only supported on Windows",
		}}}, fmt.Errorf("windows pipe controller is only supported on Windows")
	}

	httpClient, dial, err := newPipeHTTPClient(pipeName, 6*time.Second)
	if err != nil {
		return &resolvedController{attempts: []ControllerAttempt{{
			Kind:    config.ControllerModeWindowsPipe,
			Target:  pipeName,
			Success: false,
			Message: err.Error(),
		}}}, err
	}

	baseURL, _ := url.Parse(pipeBaseURL)
	var errs []string
	attempts := make([]ControllerAttempt, 0, len(secrets))

	for _, secret := range secrets {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = probeVersion(ctx, httpClient, baseURL, secret.value)
		cancel()

		attempt := ControllerAttempt{
			Kind:         config.ControllerModeWindowsPipe,
			Target:       pipeName,
			SecretSource: secret.source,
			Success:      err == nil,
		}
		if err == nil {
			attempt.Message = "GET /version succeeded"
			attempts = append(attempts, attempt)
			return &resolvedController{
				baseURL:    baseURL,
				secret:     secret.value,
				httpClient: httpClient,
				netDial:    dial,
				info: ControllerInfo{
					ConfiguredMode: mode,
					Mode:           config.ControllerModeWindowsPipe,
					BaseURL:        pipeBaseURL,
					PipeName:       pipeName,
					DisplayName:    "Windows Pipe " + pipeName,
					SupportsWS:     true,
					SecretSource:   secret.source,
				},
				attempts: attempts,
			}, nil
		}

		attempt.Message = err.Error()
		attempts = append(attempts, attempt)
		errs = append(errs, fmt.Sprintf("%s [%s]: %v", pipeName, secret.source, err))
	}

	return &resolvedController{attempts: attempts}, fmt.Errorf("windows pipe controller unavailable: %s", strings.Join(errs, "; "))
}

func probeVersion(ctx context.Context, client *http.Client, baseURL *url.URL, secret string) error {
	u := *baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expectOK(resp)
}

func httpCandidates(configURL string, includeScan bool) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 16)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			return
		}
		seen[raw] = true
		out = append(out, raw)
	}

	add(configURL)
	add("http://127.0.0.1:9097")
	add("http://127.0.0.1:9090")
	if includeScan {
		for port := 9091; port <= 9100; port++ {
			add(fmt.Sprintf("http://127.0.0.1:%d", port))
		}
	}
	return out
}

func buildSecretCandidates(userSecret string) []secretCandidate {
	seen := map[string]bool{}
	out := make([]secretCandidate, 0, 3)
	add := func(value, source string) {
		if seen[value] {
			return
		}
		seen[value] = true
		out = append(out, secretCandidate{value: value, source: source})
	}

	add(strings.TrimSpace(userSecret), "user")
	add("set-your-secret", "fallback-default")
	add("", "empty")
	return out
}

func expectOK(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("mihomo api %s: %s", resp.Status, strings.TrimSpace(string(body)))
}

func resolvedAttempts(resolved *resolvedController) []ControllerAttempt {
	if resolved == nil {
		return nil
	}
	return append([]ControllerAttempt(nil), resolved.attempts...)
}
