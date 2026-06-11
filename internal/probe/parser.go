package probe

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	matchUsingPattern = regexp.MustCompile(`(?i)match(?:ed)?\s+(.+?)\s+using\s+(.+)$`)
	ruleFragmentParen = regexp.MustCompile(`^\s*([A-Za-z0-9\-_]+)\s*\((.*)\)\s*$`)
	ruleFragmentCSV   = regexp.MustCompile(`^\s*([A-Za-z0-9\-_]+)\s*,\s*(.+?)\s*$`)
	portPattern       = regexp.MustCompile(`:(\d{1,5})\b`)
)

type ParsedLog struct {
	RuleType    string
	RulePayload string
	Policy      string
	FinalProxy  string
	Chains      []string
	Verdict     string
	DstPort     int
}

func ParseMatchLog(line string) ParsedLog {
	out := ParsedLog{Verdict: VerdictUnknown}
	m := matchUsingPattern.FindStringSubmatch(line)
	if len(m) == 3 {
		out.RuleType, out.RulePayload = parseRuleFragment(m[1])
		out.Policy, out.FinalProxy, out.Chains = parsePolicyFragment(m[2])
	}

	switch {
	case containsFold(line, "reject"):
		out.Verdict = VerdictReject
	case containsFold(line, "direct"):
		out.Verdict = VerdictDirect
	case out.FinalProxy != "" || out.Policy != "":
		out.Verdict = VerdictProxy
	}

	if match := portPattern.FindStringSubmatch(line); len(match) == 2 {
		if port, err := strconv.Atoi(match[1]); err == nil {
			out.DstPort = port
		}
	}

	return out
}

func parseRuleFragment(fragment string) (string, string) {
	fragment = strings.TrimSpace(fragment)
	if match := ruleFragmentParen.FindStringSubmatch(fragment); len(match) == 3 {
		return strings.TrimSpace(match[1]), strings.TrimSpace(match[2])
	}
	if match := ruleFragmentCSV.FindStringSubmatch(fragment); len(match) == 3 {
		return strings.TrimSpace(match[1]), strings.TrimSpace(match[2])
	}
	return "", fragment
}

func parsePolicyFragment(fragment string) (string, string, []string) {
	fragment = strings.TrimSpace(fragment)
	if fragment == "" {
		return "", "", nil
	}

	rawChains := splitChains(fragment)
	policy := ""
	finalProxy := ""
	if len(rawChains) > 0 {
		finalProxy = rawChains[0]
		policy = rawChains[len(rawChains)-1]
	}

	if len(rawChains) == 1 {
		policy = rawChains[0]
		finalProxy = rawChains[0]
	}
	return policy, finalProxy, normalizeDisplayChains(policy, finalProxy, rawChains)
}

func splitChains(fragment string) []string {
	replacer := strings.NewReplacer("->", ">", "=>", ">", "/", ">", "[", ">", "]", "", "|", ">")
	normalized := replacer.Replace(fragment)
	parts := strings.Split(normalized, ">")
	chains := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			chains = append(chains, part)
		}
	}
	return chains
}

func normalizeDisplayChains(policy, finalProxy string, rawChains []string) []string {
	display := make([]string, 0, len(rawChains))
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range display {
			if strings.EqualFold(existing, value) {
				return
			}
		}
		display = append(display, value)
	}

	add(policy)
	for i := len(rawChains) - 1; i >= 0; i-- {
		add(rawChains[i])
	}
	add(finalProxy)
	return display
}

func containsFold(s, needle string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(needle))
}
