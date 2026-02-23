package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"kiro-api-proxy/config"
	"kiro-api-proxy/kiro"
)

func getConfig(c *gin.Context) {
	cfg := config.Get()
	c.JSON(http.StatusOK, gin.H{
		"host":                cfg.Host,
		"port":                cfg.Port,
		"api_key_set":         cfg.APIKey != "",
		"allowed_ips":         cfg.AllowedIPs,
		"min_quota_remaining": cfg.MinQuotaRemaining,
		"proxy_url":           cfg.ProxyURL,
	})
}

func updateConfig(c *gin.Context) {
	var body struct {
		Host              string   `json:"host"`
		Port              string   `json:"port"`
		APIKey            *string  `json:"api_key"`
		AllowedIPs        []string `json:"allowed_ips"`
		MinQuotaRemaining *int     `json:"min_quota_remaining"`
		ProxyURL          *string  `json:"proxy_url"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cur := config.Get()
	if body.Host != "" {
		cur.Host = body.Host
	}
	if body.Port != "" {
		cur.Port = body.Port
	}
	if body.APIKey != nil {
		cur.APIKey = *body.APIKey
	}
	if body.AllowedIPs != nil {
		cur.AllowedIPs = body.AllowedIPs
	}
	if body.MinQuotaRemaining != nil {
		cur.MinQuotaRemaining = *body.MinQuotaRemaining
	}
	if body.ProxyURL != nil {
		if err := kiro.SetProxy(*body.ProxyURL); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "proxy_url 无效: " + err.Error()})
			return
		}
		cur.ProxyURL = *body.ProxyURL
	}
	if err := config.Update(cur); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "saved, restart to apply host/port changes"})
}

func startSocialLogin(c *gin.Context) {
	var body struct {
		Provider string `json:"provider"`
		Name     string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider is required (google or github)"})
		return
	}
	if body.Name == "" {
		body.Name = body.Provider + "-" + strconv.FormatInt(time.Now().Unix(), 36)
	}

	authURL, resCh, errCh, _, err := kiro.SocialLoginStart(body.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	go func() {
		select {
		case res := <-resCh:
			inp := tokenInput{
				Name:         body.Name,
				AuthMethod:   res.AuthMethod,
				AccessToken:  res.AccessToken,
				RefreshToken: res.RefreshToken,
				ProfileArn:   res.ProfileArn,
				Region:       res.Region,
				ExpiresAt:    res.ExpiresAt.Format(time.RFC3339),
			}
			if id, err := saveTokenInput(inp); err == nil {
				kiro.TriggerQuotaUpdate(id)
			}
		case <-errCh:
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
		"message":  "请在浏览器中打开 auth_url 完成登录，登录成功后 Token 将自动保存",
	})
}

func startIdCLogin(c *gin.Context) {
	var body struct {
		Region string `json:"region"`
		Name   string `json:"name"`
	}
	c.ShouldBindJSON(&body)
	if body.Region == "" {
		body.Region = "us-east-1"
	}
	if body.Name == "" {
		body.Name = "idc-" + strconv.FormatInt(time.Now().Unix(), 36)
	}

	verifyURL, userCode, resCh, errCh, _, err := kiro.IdCLoginStart(body.Region)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	go func() {
		select {
		case res := <-resCh:
			inp := tokenInput{
				Name:         body.Name,
				AuthMethod:   res.AuthMethod,
				AccessToken:  res.AccessToken,
				RefreshToken: res.RefreshToken,
				ClientID:     res.ClientID,
				ClientSecret: res.ClientSecret,
				Region:       res.Region,
				ExpiresAt:    res.ExpiresAt.Format(time.RFC3339),
			}
			if id, err := saveTokenInput(inp); err == nil {
				kiro.TriggerQuotaUpdate(id)
			}
		case <-errCh:
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"verification_url": verifyURL,
		"user_code":        userCode,
		"message":          "请在浏览器中打开 verification_url，输入 user_code 完成授权，完成后 Token 将自动保存",
	})
}
