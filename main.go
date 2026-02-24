package main

import (
	_ "embed"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"kiro-api-proxy/api"
	"kiro-api-proxy/config"
	"kiro-api-proxy/db"
	"kiro-api-proxy/kiro"
)

//go:embed web/index.html
var indexHTML []byte

func main() {
	if err := config.Load(); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cfg := config.Get()

	// 应用已保存的代理配置
	if cfg.ProxyURL != "" {
		if err := kiro.SetProxy(cfg.ProxyURL); err != nil {
			log.Printf("warning: invalid proxy_url in config: %v", err)
		} else {
			log.Printf("using proxy: %s", cfg.ProxyURL)
		}
	}

	if err := db.Init("./kiro.db"); err != nil {
		log.Fatalf("failed to init db: %v", err)
	}

	kiro.StartAutoRefresh(10 * time.Minute)

	r := gin.Default()
	api.SetupRoutes(r, cfg.APIKey, indexHTML)

	addr := cfg.Host + ":" + cfg.Port
	log.Printf("Kiro API Proxy listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}
