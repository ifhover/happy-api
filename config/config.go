package config

import (
	"encoding/json"
	"net"
	"os"
	"sync"
)

const ConfigFile = "./config.json"

type Config struct {
	Host              string   `json:"host"`
	Port              string   `json:"port"`
	APIKey            string   `json:"api_key"`
	AllowedIPs        []string `json:"allowed_ips"`
	MinQuotaRemaining int      `json:"min_quota_remaining"` // 低于此值不优先使用，0 表示不限制
	ProxyURL          string   `json:"proxy_url"`           // 代理地址，留空则使用系统代理
}

var (
	mu  sync.RWMutex
	cfg Config
)

func Load() error {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(ConfigFile)
	if os.IsNotExist(err) {
		// 首次运行写入默认配置
		cfg = Config{Host: "0.0.0.0", Port: "8080", APIKey: "", AllowedIPs: []string{}}
		return save()
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &cfg)
}

func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return cfg
}

func Update(c Config) error {
	mu.Lock()
	defer mu.Unlock()
	cfg = c
	return save()
}

func save() error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFile, data, 0644)
}

// IsAllowed 检查 IP 是否在白名单中，白名单为空则放行所有
func IsAllowed(remoteAddr string) bool {
	mu.RLock()
	allowed := cfg.AllowedIPs
	mu.RUnlock()

	if len(allowed) == 0 {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)

	for _, entry := range allowed {
		// 支持 CIDR 和单 IP
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if ip != nil && cidr.Contains(ip) {
				return true
			}
		} else if net.ParseIP(entry) != nil {
			if host == entry {
				return true
			}
		}
	}
	return false
}
