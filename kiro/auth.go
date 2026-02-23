package kiro

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authServiceEndpoint = "https://prod.us-east-1.auth.desktop.kiro.dev"
	ssoOIDCEndpoint     = "https://oidc.%s.amazonaws.com"
	builderIDStartURL   = "https://view.awsapps.com/start"
	callbackPortStart   = 19876
	callbackPortEnd     = 19880
)

var ssoScopes = []string{
	"codewhisperer:completions",
	"codewhisperer:analysis",
	"codewhisperer:conversations",
}

// LoginResult 登录成功后返回的凭证
type LoginResult struct {
	AccessToken           string
	RefreshToken          string
	ProfileArn            string
	ClientID              string
	ClientSecret          string
	AuthMethod            string
	Region                string
	ExpiresAt             time.Time
	RegistrationExpiresAt time.Time
}

// ── PKCE 工具 ─────────────────────────────────────────────────

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ── Social Auth（Google / GitHub）────────────────────────────

// SocialLoginStart 启动 Social Auth 登录，返回授权 URL 和一个 channel 等待结果
// provider: "google" 或 "github"
func SocialLoginStart(provider string) (authURL string, result <-chan LoginResult, errCh <-chan error, cancel func(), err error) {
	verifier, err := generateCodeVerifier()
	if err != nil {
		return "", nil, nil, nil, err
	}
	challenge := generateCodeChallenge(verifier)
	state, err := generateState()
	if err != nil {
		return "", nil, nil, nil, err
	}

	// 找一个可用端口
	port, err := findFreePort(callbackPortStart, callbackPortEnd)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("no free port in range %d-%d", callbackPortStart, callbackPortEnd)
	}

	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", port)

	q := url.Values{}
	q.Set("idp", provider)
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("prompt", "select_account")
	authURL = authServiceEndpoint + "/login?" + q.Encode()

	resCh := make(chan LoginResult, 1)
	errChan := make(chan error, 1)

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Minute)

	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port)}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errParam := q.Get("error"); errParam != "" {
			writeCallbackPage(w, false, "授权失败: "+errParam)
			errChan <- fmt.Errorf("oauth error: %s", errParam)
			go srv.Shutdown(context.Background())
			return
		}
		if q.Get("state") != state {
			writeCallbackPage(w, false, "state 验证失败，请重试")
			errChan <- fmt.Errorf("state mismatch")
			go srv.Shutdown(context.Background())
			return
		}
		code := q.Get("code")
		if code == "" {
			writeCallbackPage(w, false, "未收到授权码")
			errChan <- fmt.Errorf("missing code")
			go srv.Shutdown(context.Background())
			return
		}

		// 用 code 换 token
		res, err := exchangeSocialToken(code, verifier, redirectURI)
		if err != nil {
			writeCallbackPage(w, false, "获取 Token 失败: "+err.Error())
			errChan <- err
			go srv.Shutdown(context.Background())
			return
		}

		writeCallbackPage(w, true, "登录成功，可以关闭此页面")
		resCh <- *res
		go srv.Shutdown(context.Background())
	})
	srv.Handler = mux

	go func() {
		defer cancelFn()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// 超时自动关闭
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
		if ctx.Err() == context.DeadlineExceeded {
			errChan <- fmt.Errorf("login timeout")
		}
	}()

	cancel = func() {
		cancelFn()
		srv.Shutdown(context.Background())
	}

	return authURL, resCh, errChan, cancel, nil
}

func exchangeSocialToken(code, verifier, redirectURI string) (*LoginResult, error) {
	body, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  redirectURI,
	})
	resp, err := doPost(authServiceEndpoint+"/oauth/token", body, map[string]string{
		"User-Agent": "KiroIDE/" + kiroVersion,
	}, refreshClient)
	if err != nil {
		return nil, err
	}

	var r struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ProfileArn   string `json:"profileArn"`
		ExpiresIn    int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, err
	}
	if r.AccessToken == "" {
		return nil, fmt.Errorf("empty access token in response")
	}

	expiresIn := r.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 3600
	}
	return &LoginResult{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		ProfileArn:   r.ProfileArn,
		AuthMethod:   "social",
		Region:       "us-east-1",
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// ── Builder ID（IdC）Device Code 流程 ─────────────────────────

// IdCLoginStart 启动 Builder ID 登录，返回用户需要访问的 URL 和 userCode，
// 以及一个 channel 等待轮询结果
func IdCLoginStart(region string) (verificationURL, userCode string, result <-chan LoginResult, errCh <-chan error, cancel func(), err error) {
	if region == "" {
		region = "us-east-1"
	}
	oidcBase := fmt.Sprintf(ssoOIDCEndpoint, region)

	// 1. 注册 OIDC 客户端
	regBody, _ := json.Marshal(map[string]interface{}{
		"clientName": "Kiro IDE",
		"clientType": "public",
		"scopes":     ssoScopes,
	})
	regResp, err := doPost(oidcBase+"/client/register", regBody, map[string]string{
		"User-Agent": "KiroIDE/" + kiroVersion,
	}, refreshClient)
	if err != nil {
		return "", "", nil, nil, nil, fmt.Errorf("client register: %w", err)
	}
	var reg struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.Unmarshal(regResp, &reg); err != nil {
		return "", "", nil, nil, nil, err
	}

	// 2. 启动设备授权
	authBody, _ := json.Marshal(map[string]string{
		"clientId":     reg.ClientID,
		"clientSecret": reg.ClientSecret,
		"startUrl":     builderIDStartURL,
	})
	authResp, err := doPost(oidcBase+"/device_authorization", authBody, nil, refreshClient)
	if err != nil {
		return "", "", nil, nil, nil, fmt.Errorf("device authorization: %w", err)
	}
	var device struct {
		DeviceCode              string `json:"deviceCode"`
		UserCode                string `json:"userCode"`
		VerificationURI         string `json:"verificationUri"`
		VerificationURIComplete string `json:"verificationUriComplete"`
		ExpiresIn               int    `json:"expiresIn"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(authResp, &device); err != nil {
		return "", "", nil, nil, nil, err
	}

	vURL := device.VerificationURIComplete
	if vURL == "" {
		vURL = device.VerificationURI
	}
	interval := device.Interval
	if interval == 0 {
		interval = 5
	}
	expiresIn := device.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 600
	}

	resCh := make(chan LoginResult, 1)
	errChan := make(chan error, 1)
	ctx, cancelFn := context.WithTimeout(context.Background(), time.Duration(expiresIn)*time.Second)

	// 3. 后台轮询
	go func() {
		defer cancelFn()
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				errChan <- fmt.Errorf("login timeout or cancelled")
				return
			case <-ticker.C:
				tokenBody, _ := json.Marshal(map[string]string{
					"clientId":     reg.ClientID,
					"clientSecret": reg.ClientSecret,
					"deviceCode":   device.DeviceCode,
					"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
				})
				resp, err := pollIdCToken(oidcBase+"/token", tokenBody)
				if err != nil {
					// authorization_pending / slow_down 继续等
					if strings.Contains(err.Error(), "authorization_pending") {
						continue
					}
					if strings.Contains(err.Error(), "slow_down") {
						ticker.Reset(time.Duration(interval+5) * time.Second)
						continue
					}
					errChan <- err
					return
				}
				expiresAt := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
				resCh <- LoginResult{
					AccessToken:  resp.AccessToken,
					RefreshToken: resp.RefreshToken,
					ClientID:     reg.ClientID,
					ClientSecret: reg.ClientSecret,
					AuthMethod:   "builder-id",
					Region:       region,
					ExpiresAt:    expiresAt,
				}
				return
			}
		}
	}()

	cancel = func() {
		cancelFn()
	}

	return vURL, device.UserCode, resCh, errChan, cancel, nil
}

type idcTokenResp struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
}

func pollIdCToken(endpoint string, body []byte) (*idcTokenResp, error) {
	req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KiroIDE/"+kiroVersion)

	resp, err := refreshClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		if e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, data)
	}

	var r idcTokenResp
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.AccessToken == "" {
		return nil, fmt.Errorf("authorization_pending")
	}
	return &r, nil
}

// ── 工具函数 ──────────────────────────────────────────────────

func findFreePort(start, end int) (int, error) {
	for p := start; p <= end; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free port")
}

func writeCallbackPage(w http.ResponseWriter, success bool, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	icon := "✅"
	color := "#4ade80"
	if !success {
		icon = "❌"
		color = "#f87171"
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:-apple-system,sans-serif;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
.box{text-align:center;padding:40px;background:#161b27;border-radius:12px;border:1px solid #1e2433;}
.icon{font-size:48px;margin-bottom:16px;} .msg{color:%s;font-size:16px;}</style></head>
<body><div class="box"><div class="icon">%s</div><div class="msg">%s</div></div></body></html>`,
		color, icon, msg)
}
