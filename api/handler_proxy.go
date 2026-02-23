package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"kiro-api-proxy/config"
	"kiro-api-proxy/db"
	"kiro-api-proxy/kiro"
)

var (
	lastTokenID int64
	tokenMu     sync.Mutex
)

func pickToken() (*db.Token, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	minQuota := config.Get().MinQuotaRemaining
	token, err := db.GetNextEligibleToken(lastTokenID, minQuota)
	if err != nil {
		return nil, err
	}
	lastTokenID = token.ID
	return token, nil
}

func handleOpenAI(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	token, err := pickToken()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no available token: " + err.Error()})
		return
	}

	// 检查是否请求流式响应
	var req struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &req)

	if req.Stream {
		if err := kiro.ProxyOpenAIStream(c, token, body); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		}
		return
	}

	respBody, statusCode, err := kiro.ProxyOpenAI(token, body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Data(statusCode, "application/json", respBody)
}

func handleClaude(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	token, err := pickToken()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no available token: " + err.Error()})
		return
	}

	// 检查是否请求流式响应
	var req struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &req)

	if req.Stream {
		if err := kiro.ProxyClaudeStream(c, token, body); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		}
		return
	}

	respBody, statusCode, err := kiro.ProxyClaude(token, body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Data(statusCode, "application/json", respBody)
}
