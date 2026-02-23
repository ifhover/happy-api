package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"kiro-api-proxy/config"
)

func SetupRoutes(r *gin.Engine, apiKey string) {
	// 管理接口：受 IP 白名单保护
	admin := r.Group("/")
	admin.Use(ipWhitelistMiddleware())
	{
		admin.GET("/", func(c *gin.Context) { c.File("./web/index.html") })

		admin.GET("/api/config", getConfig)
		admin.PUT("/api/config", updateConfig)

		admin.POST("/api/login/social", startSocialLogin)
		admin.POST("/api/login/idc", startIdCLogin)

		mgmt := admin.Group("/api/tokens")
		mgmt.GET("", listTokens)
		mgmt.POST("", createToken)
		mgmt.POST("/import", importTokens)
		mgmt.DELETE("/:id", deleteToken)
		mgmt.PATCH("/:id/enabled", toggleEnabled)
		mgmt.POST("/:id/refresh", refreshToken)
		mgmt.POST("/:id/check-quota", checkQuota)
	}

	// AI 代理接口：API key 鉴权，不受 IP 白名单限制
	proxy := r.Group("/")
	if apiKey != "" {
		proxy.Use(apiKeyMiddleware(apiKey))
	}
	proxy.POST("/v1/chat/completions", handleOpenAI)
	proxy.POST("/v1/messages", handleClaude)
}

func ipWhitelistMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.IsAllowed(c.Request.RemoteAddr) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "IP not allowed"})
			return
		}
		c.Next()
	}
}

func apiKeyMiddleware(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := ""
		if auth := c.GetHeader("Authorization"); auth != "" {
			if len(auth) > 7 && auth[:7] == "Bearer " {
				key = auth[7:]
			} else {
				key = auth
			}
		}
		if key == "" {
			key = c.GetHeader("x-api-key")
		}
		if key != apiKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
			return
		}
		c.Next()
	}
}
