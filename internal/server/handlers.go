package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/mihomo"
	"mihomo-rule-inspector/internal/probe"
)

func CheckController(ctx context.Context, cfg config.AppConfig) (map[string]any, error) {
	client, err := mihomo.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	version, versionErr := client.GetVersion(ctx)
	_, configsErr := client.GetConfigs(ctx)
	result := map[string]any{
		"controller": client.Info(),
		"attempts":   client.Attempts(),
		"version":    version,
		"ok":         versionErr == nil && configsErr == nil,
	}
	if versionErr != nil || configsErr != nil {
		result["errors"] = map[string]string{"version": errString(versionErr), "configs": errString(configsErr)}
	}
	return result, nil
}

func BatchProbe(ctx context.Context, cfg config.AppConfig, req probe.BatchProbeRequest) ([]probe.Diagnosis, error) {
	service, err := probe.NewService(cfg)
	if err != nil {
		return nil, err
	}
	results := make([]probe.Diagnosis, 0, len(req.Targets))
	for _, target := range req.Targets {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		item := runBatchProbeItem(ctx, service, probe.ProbeRequest{
			Target: target, ClearDNSCache: req.ClearDNSCache,
			ClearFakeIPCache: req.ClearFakeIPCache, TimeoutMs: req.TimeoutMs,
		})
		results = append(results, item)
	}
	return results, nil
}

type RulesResult struct {
	Rules         map[string]any
	Providers     map[string]any
	Candidates    []map[string]any
	Target        string
	RulesError    string
	ProviderError string
}

func Rules(ctx context.Context, cfg config.AppConfig, target string) (RulesResult, error) {
	client, err := mihomo.NewClient(cfg)
	if err != nil {
		return RulesResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rules, rulesErr := client.GetRules(ctx)
	providers, providersErr := client.GetRuleProviders(ctx)
	host, _ := probe.NormalizeTarget(target)
	return RulesResult{
		Rules: rules, Providers: providers, Candidates: weakMatchCandidates(host, rules), Target: host,
		RulesError: errString(rulesErr), ProviderError: errString(providersErr),
	}, nil
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
