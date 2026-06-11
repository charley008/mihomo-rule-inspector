package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/mihomo"
	"mihomo-rule-inspector/internal/probe"
)

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.currentConfig()
		configPath, _ := config.Path()
		s.writeJSON(w, http.StatusOK, map[string]any{
			"controllerMode":              cfg.ControllerMode,
			"controllerUrl":               cfg.ControllerURL,
			"controllerPipe":              cfg.ControllerPipe,
			"secret":                      cfg.Secret,
			"mixedProxyUrl":               cfg.MixedProxyURL,
			"timeoutMs":                   cfg.TimeoutMs,
			"clearDnsCacheBeforeProbe":    cfg.ClearDNSCacheBeforeProbe,
			"clearFakeIpCacheBeforeProbe": cfg.ClearFakeIPCacheBeforeProbe,
			"configPath":                  configPath,
		})
	case http.MethodPost:
		var cfg config.AppConfig
		if err := s.decodeJSON(r, &cfg); err != nil {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		cfg.ControllerMode = strings.TrimSpace(cfg.ControllerMode)
		cfg.ControllerURL = strings.TrimSpace(cfg.ControllerURL)
		cfg.ControllerPipe = strings.TrimSpace(cfg.ControllerPipe)
		cfg.MixedProxyURL = strings.TrimSpace(cfg.MixedProxyURL)
		if err := s.updateConfig(cfg); err != nil {
			s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		configPath, _ := config.Path()
		s.writeJSON(w, http.StatusOK, map[string]any{
			"controllerMode":              cfg.ControllerMode,
			"controllerUrl":               cfg.ControllerURL,
			"controllerPipe":              cfg.ControllerPipe,
			"secret":                      cfg.Secret,
			"mixedProxyUrl":               cfg.MixedProxyURL,
			"timeoutMs":                   cfg.TimeoutMs,
			"clearDnsCacheBeforeProbe":    cfg.ClearDNSCacheBeforeProbe,
			"clearFakeIpCacheBeforeProbe": cfg.ClearFakeIPCacheBeforeProbe,
			"configPath":                  configPath,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	detection, err := mihomo.DetectController(s.currentConfig())
	if err != nil {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"error":      err.Error(),
			"controller": detection.Info,
			"attempts":   detection.Attempts,
		})
		return
	}

	client, err := mihomo.NewClient(s.currentConfig())
	if err != nil {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"error":      err.Error(),
			"controller": detection.Info,
			"attempts":   detection.Attempts,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	version, versionErr := client.GetVersion(ctx)
	configs, configsErr := client.GetConfigs(ctx)
	ok := versionErr == nil && configsErr == nil

	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":         ok,
		"version":    version,
		"configs":    configs,
		"controller": client.Info(),
		"attempts":   detection.Attempts,
		"errors": map[string]string{
			"version": errString(versionErr),
			"configs": errString(configsErr),
		},
	})
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req probe.ProbeRequest
	if err := s.decodeJSON(r, &req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	service, err := probe.NewService(s.currentConfig())
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	result, err := service.Run(r.Context(), req)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleBatchProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req probe.BatchProbeRequest
	if err := s.decodeJSON(r, &req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	service, err := probe.NewService(s.currentConfig())
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	results := make([]probe.Diagnosis, 0, len(req.Targets))
	for _, target := range req.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		item := runBatchProbeItem(r.Context(), service, probe.ProbeRequest{
			Target:           target,
			ClearDNSCache:    req.ClearDNSCache,
			ClearFakeIPCache: req.ClearFakeIPCache,
			TimeoutMs:        req.TimeoutMs,
		})
		results = append(results, item)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"results":     results,
		"concurrency": 1,
	})
}

func runBatchProbeItem(ctx context.Context, service *probe.Service, req probe.ProbeRequest) probe.Diagnosis {
	const maxAttempts = 5

	var last probe.Diagnosis
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		item, err := service.Run(ctx, req)
		if err != nil {
			last = probe.Diagnosis{
				Target:      req.Target,
				Verdict:     probe.VerdictUnknown,
				Error:       err.Error(),
				Suggestions: []string{"批量探测时当前项执行失败，请先检查上游配置是否可用。"},
			}
			break
		}

		last = item
		if len(item.RawConnection) > 0 {
			if attempt > 1 {
				last.Suggestions = append(last.Suggestions,
					fmt.Sprintf("批量检测在第 %d 次尝试时拿到了有效连接证据。", attempt),
				)
			}
			return last
		}

		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				last.Error = "批量检测已取消。"
				return last
			case <-time.After(300 * time.Millisecond):
			}
		}
	}

	if len(last.RawConnection) == 0 && last.Error == "" {
		last.Error = fmt.Sprintf("连续 %d 次尝试后仍未拿到 /connections 证据。", maxAttempts)
	}
	if len(last.RawConnection) == 0 {
		last.Suggestions = append(last.Suggestions,
			"批量检测会在拿不到连接证据时自动重试，但当前项仍未成功，建议单独用快速检测再试一次。",
		)
	}
	return last
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	client, err := mihomo.NewClient(s.currentConfig())
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rules, rulesErr := client.GetRules(ctx)
	providers, providersErr := client.GetRuleProviders(ctx)
	host, _ := probe.NormalizeTarget(r.URL.Query().Get("target"))

	s.writeJSON(w, http.StatusOK, map[string]any{
		"rules":         rules,
		"providers":     providers,
		"candidates":    weakMatchCandidates(host, rules),
		"target":        host,
		"rulesError":    errString(rulesErr),
		"providerError": errString(providersErr),
	})
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	client, err := mihomo.NewClient(s.currentConfig())
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	snapshot, err := client.GetConnections(ctx)
	if err != nil {
		s.writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 300
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	lines := []string{}
	if s.logs != nil {
		lines = s.logs.Snapshot(limit)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"logs": lines,
	})
}

func (s *Server) handleLogsWS(w http.ResponseWriter, r *http.Request) {
	downstream, client, ctx, cleanup, ok := s.prepareWS(w, r)
	if !ok {
		return
	}
	defer cleanup()

	upstream, err := client.OpenLogsStream(ctx, "info")
	if err == nil {
		defer upstream.Close()
		proxyBidirectionalWS(downstream, upstream)
		return
	}

	_ = downstream.WriteJSON(map[string]any{
		"error": fmt.Sprintf("日志 WebSocket 不可用：%v", err),
	})
}

func (s *Server) handleConnectionsWS(w http.ResponseWriter, r *http.Request) {
	downstream, client, ctx, cleanup, ok := s.prepareWS(w, r)
	if !ok {
		return
	}
	defer cleanup()

	upstream, err := client.OpenConnectionsStream(ctx)
	if err == nil {
		defer upstream.Close()
		proxyBidirectionalWS(downstream, upstream)
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		snapshot, fetchErr := client.GetConnections(ctx)
		if fetchErr != nil {
			_ = downstream.WriteJSON(map[string]any{"error": fetchErr.Error()})
		} else {
			_ = downstream.WriteJSON(snapshot)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) prepareWS(w http.ResponseWriter, r *http.Request) (*websocket.Conn, *mihomo.Client, context.Context, func(), bool) {
	client, err := mihomo.NewClient(s.currentConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, nil, nil, nil, false
	}

	downstream, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, nil, nil, nil, false
	}

	ctx, cancel := context.WithCancel(r.Context())
	cleanup := func() {
		cancel()
		_ = downstream.Close()
	}

	return downstream, client, ctx, cleanup, true
}

func proxyBidirectionalWS(downstream, upstream *websocket.Conn) {
	errCh := make(chan error, 2)
	go copyWS(errCh, upstream, downstream)
	go copyWS(errCh, downstream, upstream)
	<-errCh
}

func copyWS(errCh chan<- error, src, dst *websocket.Conn) {
	for {
		messageType, payload, err := src.ReadMessage()
		if err != nil {
			errCh <- err
			return
		}
		if err := dst.WriteMessage(messageType, payload); err != nil {
			errCh <- err
			return
		}
	}
}

func weakMatchCandidates(host string, rules map[string]any) []map[string]any {
	if host == "" || rules == nil {
		return nil
	}

	rawRules, ok := rules["rules"].([]any)
	if !ok {
		return nil
	}

	results := make([]map[string]any, 0)
	for idx, item := range rawRules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}

		ruleType := strings.ToUpper(strings.TrimSpace(asString(rule["type"])))
		payload := strings.TrimSpace(asString(rule["payload"]))
		matchType := ""

		switch ruleType {
		case "DOMAIN":
			if strings.EqualFold(host, payload) {
				matchType = "exact"
			}
		case "DOMAIN-SUFFIX":
			if strings.EqualFold(host, payload) || strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(payload)) {
				matchType = "suffix"
			}
		case "DOMAIN-KEYWORD":
			if strings.Contains(strings.ToLower(host), strings.ToLower(payload)) {
				matchType = "keyword"
			}
		case "DOMAIN-WILDCARD":
			if wildcardMatch(strings.ToLower(payload), strings.ToLower(host)) {
				matchType = "wildcard"
			}
		case "DOMAIN-REGEX":
			if payload != "" && strings.Contains(strings.ToLower(host), strings.ToLower(strings.Trim(payload, "^$"))) {
				matchType = "weak-regex"
			}
		case "MATCH":
			matchType = "fallback"
		case "GEOIP", "GEOSITE", "RULE-SET", "PROCESS-NAME", "PROCESS-PATH", "SUB-RULE", "AND", "OR", "NOT":
			matchType = "display-only"
		}

		if matchType != "" {
			results = append(results, map[string]any{
				"index":     idx,
				"type":      ruleType,
				"payload":   payload,
				"proxy":     asString(rule["proxy"]),
				"matchType": matchType,
				"raw":       rule,
			})
		}
	}

	return results
}

func wildcardMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(value, part) && !strings.HasPrefix(pattern, "*") {
			return false
		}
		pos += idx + len(part)
	}
	last := parts[len(parts)-1]
	return last == "" || strings.HasSuffix(value, last) || strings.HasSuffix(pattern, "*")
}

func asString(v any) string {
	switch value := v.(type) {
	case string:
		return value
	default:
		return fmt.Sprintf("%v", value)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
