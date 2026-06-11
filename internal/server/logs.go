package server

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/mihomo"
)

const maxLogLines = 1000

type LogCollector struct {
	getConfig func() config.AppConfig

	mu     sync.RWMutex
	lines  []string
	cancel context.CancelFunc
}

func NewLogCollector(getConfig func() config.AppConfig) *LogCollector {
	c := &LogCollector{getConfig: getConfig}
	c.Restart()
	return c
}

func (c *LogCollector) Restart() {
	c.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()

	go c.run(ctx)
}

func (c *LogCollector) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *LogCollector) Snapshot(limit int) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 || limit > len(c.lines) {
		limit = len(c.lines)
	}
	if limit == 0 {
		return []string{}
	}

	start := len(c.lines) - limit
	out := make([]string, limit)
	copy(out, c.lines[start:])
	return out
}

func (c *LogCollector) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		client, err := mihomo.NewClient(c.getConfig())
		if err != nil {
			if !sleepOrDone(ctx, 3*time.Second) {
				return
			}
			continue
		}

		conn, err := client.OpenLogsStream(ctx, "info")
		if err != nil {
			if !sleepOrDone(ctx, 3*time.Second) {
				return
			}
			continue
		}

		c.readLoop(ctx, conn)
		_ = conn.Close()

		if !sleepOrDone(ctx, 1500*time.Millisecond) {
			return
		}
	}
}

func (c *LogCollector) readLoop(ctx context.Context, conn *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		c.appendLog(extractLogLine(payload))
	}
}

func (c *LogCollector) appendLog(line string) {
	if line == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.lines = append(c.lines, line)
	if len(c.lines) > maxLogLines {
		c.lines = append([]string{}, c.lines[len(c.lines)-maxLogLines:]...)
	}
}

func extractLogLine(payload []byte) string {
	var wrapped map[string]any
	if err := json.Unmarshal(payload, &wrapped); err == nil {
		if line, ok := wrapped["payload"].(string); ok && line != "" {
			return line
		}
	}
	return string(payload)
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
