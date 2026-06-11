package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const (
	ControllerModeAuto        = "auto"
	ControllerModeHTTP        = "http"
	ControllerModeWindowsPipe = "windows_pipe"
	DefaultControllerPipe     = `\\.\pipe\verge-mihomo`
)

type AppConfig struct {
	ControllerMode              string `json:"controllerMode"`
	ControllerURL               string `json:"controllerUrl"`
	ControllerPipe              string `json:"controllerPipe"`
	Secret                      string `json:"secret"`
	MixedProxyURL               string `json:"mixedProxyUrl"`
	ListenAddr                  string `json:"listenAddr"`
	TimeoutMs                   int    `json:"timeoutMs"`
	ClearDNSCacheBeforeProbe    bool   `json:"clearDnsCacheBeforeProbe"`
	ClearFakeIPCacheBeforeProbe bool   `json:"clearFakeIpCacheBeforeProbe"`
}

func Default() AppConfig {
	return AppConfig{
		ControllerMode:              ControllerModeHTTP,
		ControllerURL:               "http://127.0.0.1:9090",
		ControllerPipe:              DefaultControllerPipe,
		MixedProxyURL:               "http://127.0.0.1:10801",
		ListenAddr:                  "127.0.0.1:8787",
		TimeoutMs:                   5000,
		ClearDNSCacheBeforeProbe:    false,
		ClearFakeIPCacheBeforeProbe: false,
	}
}

func Load() (AppConfig, error) {
	cfg := Default()
	path, err := Path()
	if err != nil {
		return cfg, err
	}

	if err := EnsureFiles(path); err != nil {
		return cfg, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	cfg.applyDefaults()
	return cfg, nil
}

func Save(cfg AppConfig) error {
	cfg.applyDefaults()
	path, err := Path()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

func Path() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	return filepath.Join(filepath.Dir(exePath), "data", "config.json"), nil
}

func EnsureFiles(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := ensureFile(path, configJSON()); err != nil {
		return err
	}
	if err := ensureFile(filepath.Join(dir, "config.example.json"), configExampleJSON()); err != nil {
		return err
	}
	return nil
}

func ensureFile(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func configJSON() string {
	return `{
  "controllerMode": "http",
  "controllerUrl": "http://127.0.0.1:9090",
  "controllerPipe": "\\\\.\\pipe\\verge-mihomo",
  "secret": "",
  "mixedProxyUrl": "http://127.0.0.1:10801",
  "listenAddr": "127.0.0.1:8787",
  "timeoutMs": 5000,
  "clearDnsCacheBeforeProbe": false,
  "clearFakeIpCacheBeforeProbe": false
}
`
}

func configExampleJSON() string {
	return `{
  "_comment": "这是示例配置文件。程序真正读取的是同目录下的 config.json。",
  "_comment_controllerMode": "controller 模式，可选 http、windows_pipe。旧版本里的 auto 会按 http 兼容处理，但不再自动扫描端口。",
  "controllerMode": "http",

  "_comment_controllerUrl": "HTTP controller 地址。程序只测试你这里填写的地址，不再自动扫描 9097、9090 或其他端口。",
  "controllerUrl": "http://127.0.0.1:9090",

  "_comment_controllerPipe": "Windows Pipe controller 名称。Clash Verge Dev/Rev 常见值是 \\\\.\\pipe\\verge-mihomo。",
  "controllerPipe": "\\\\.\\pipe\\verge-mihomo",

  "_comment_secret": "Mihomo 的 secret。程序只测试你当前填写的值；如果留空，就只按空 secret 测试一次。",
  "secret": "",

  "_comment_mixedProxyUrl": "mixed-port 地址。注意：探测流量始终走 mixed-port，不走 named pipe。",
  "mixedProxyUrl": "http://127.0.0.1:10801",

  "_comment_listenAddr": "兼容模式保留字段。当前桌面版窗口模式下通常不会直接使用这个地址。",
  "listenAddr": "127.0.0.1:8787",

  "_comment_timeoutMs": "单次探测超时，单位毫秒。",
  "timeoutMs": 5000,

  "_comment_clearDnsCacheBeforeProbe": "每次探测前是否自动清理 Mihomo 的 DNS 缓存。",
  "clearDnsCacheBeforeProbe": false,

  "_comment_clearFakeIpCacheBeforeProbe": "每次探测前是否自动清理 Mihomo 的 fake-ip 缓存。",
  "clearFakeIpCacheBeforeProbe": false
}
`
}

func (c *AppConfig) applyDefaults() {
	def := Default()
	if c.ControllerMode == "" || c.ControllerMode == ControllerModeAuto {
		c.ControllerMode = def.ControllerMode
	}
	if c.ControllerURL == "" {
		c.ControllerURL = def.ControllerURL
	}
	if c.ControllerPipe == "" {
		c.ControllerPipe = def.ControllerPipe
	}
	if c.MixedProxyURL == "" {
		c.MixedProxyURL = def.MixedProxyURL
	}
	if c.ListenAddr == "" {
		c.ListenAddr = def.ListenAddr
	}
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = def.TimeoutMs
	}
}
