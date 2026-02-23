package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"kiro-api-proxy/db"
	"kiro-api-proxy/kiro"
)

type safeToken struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	AuthMethod     string     `json:"auth_method"`
	Region         string     `json:"region"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Enabled        bool       `json:"enabled"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	CreatedAt      time.Time  `json:"created_at"`
	QuotaTotal     int        `json:"quota_total"`
	QuotaUsed      int        `json:"quota_used"`
	QuotaCheckedAt *time.Time `json:"quota_checked_at"`
	IsExpired      bool       `json:"is_expired"`
}

// tokenInput 是创建/导入 token 的通用输入结构（snake_case）
type tokenInput struct {
	Name                  string `json:"name"`
	AuthMethod            string `json:"auth_method"`
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	ProfileArn            string `json:"profile_arn"`
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	Region                string `json:"region"`
	ExpiresAt             string `json:"expires_at"`
	RegistrationExpiresAt string `json:"registration_expires_at"`
}

// rawTokenJSON 对应 kiro-auth-token.json 的原始字段名（camelCase）
type rawTokenJSON struct {
	AccessToken           string `json:"accessToken"`
	RefreshToken          string `json:"refreshToken"`
	ProfileArn            string `json:"profileArn"`
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	AuthMethod            string `json:"authMethod"`
	Region                string `json:"region"`
	IdcRegion             string `json:"idcRegion"`
	ExpiresAt             string `json:"expiresAt"`
	RegistrationExpiresAt string `json:"registrationExpiresAt"`
}

func (r rawTokenJSON) toInput(name string) tokenInput {
	region := r.Region
	if region == "" {
		region = r.IdcRegion
	}
	authMethod := r.AuthMethod
	if authMethod == "" {
		if r.ProfileArn != "" {
			authMethod = "social"
		} else {
			authMethod = "builder-id"
		}
	}
	return tokenInput{
		Name:                  name,
		AuthMethod:            authMethod,
		AccessToken:           r.AccessToken,
		RefreshToken:          r.RefreshToken,
		ProfileArn:            r.ProfileArn,
		ClientID:              r.ClientID,
		ClientSecret:          r.ClientSecret,
		Region:                region,
		ExpiresAt:             r.ExpiresAt,
		RegistrationExpiresAt: r.RegistrationExpiresAt,
	}
}

func saveTokenInput(inp tokenInput) (int64, error) {
	expiresAt, err := time.Parse(time.RFC3339, inp.ExpiresAt)
	if err != nil {
		expiresAt, err = time.Parse("2006-01-02T15:04:05.000Z", inp.ExpiresAt)
		if err != nil {
			expiresAt = time.Now().Add(time.Hour)
		}
	}
	region := inp.Region
	if region == "" {
		region = "us-east-1"
	}
	t := &db.Token{
		Name:         inp.Name,
		AuthMethod:   inp.AuthMethod,
		AccessToken:  inp.AccessToken,
		RefreshToken: inp.RefreshToken,
		ProfileArn:   inp.ProfileArn,
		ClientID:     inp.ClientID,
		ClientSecret: inp.ClientSecret,
		Region:       region,
		ExpiresAt:    expiresAt,
		Enabled:      true,
	}
	if inp.RegistrationExpiresAt != "" {
		t.RegistrationExpiresAt, _ = time.Parse(time.RFC3339, inp.RegistrationExpiresAt)
	}
	return db.CreateToken(t)
}

func validateTokenInput(inp tokenInput) error {
	expiresAt, _ := time.Parse(time.RFC3339, inp.ExpiresAt)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour)
	}
	region := inp.Region
	if region == "" {
		region = "us-east-1"
	}
	t := &db.Token{
		AuthMethod:   inp.AuthMethod,
		AccessToken:  inp.AccessToken,
		RefreshToken: inp.RefreshToken,
		ProfileArn:   inp.ProfileArn,
		ClientID:     inp.ClientID,
		ClientSecret: inp.ClientSecret,
		Region:       region,
		ExpiresAt:    expiresAt,
	}
	return kiro.ValidateToken(t)
}

func listTokens(c *gin.Context) {
	tokens, err := db.ListTokens()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	result := make([]safeToken, 0, len(tokens))
	for _, t := range tokens {
		result = append(result, safeToken{
			ID:             t.ID,
			Name:           t.Name,
			AuthMethod:     t.AuthMethod,
			Region:         t.Region,
			ExpiresAt:      t.ExpiresAt,
			Enabled:        t.Enabled,
			LastUsedAt:     t.LastUsedAt,
			CreatedAt:      t.CreatedAt,
			QuotaTotal:     t.QuotaTotal,
			QuotaUsed:      t.QuotaUsed,
			QuotaCheckedAt: t.QuotaCheckedAt,
			IsExpired:      time.Now().After(t.ExpiresAt),
		})
	}
	c.JSON(http.StatusOK, result)
}

func createToken(c *gin.Context) {
	var inp tokenInput
	if err := c.ShouldBindJSON(&inp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if inp.AccessToken == "" || inp.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access_token and refresh_token are required"})
		return
	}
	if inp.Name == "" {
		inp.Name = "token-" + strconv.FormatInt(time.Now().Unix(), 36)
	}
	if err := validateTokenInput(inp); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "token validation failed: " + err.Error()})
		return
	}
	id, err := saveTokenInput(inp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	kiro.TriggerQuotaUpdate(id)
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// importTokens 支持三种格式：
//  1. 单个 rawTokenJSON（camelCase，即 kiro-auth-token.json 格式）
//  2. rawTokenJSON 数组
//  3. tokenInput / tokenInput 数组（snake_case）
func importTokens(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	inputs := parseImportBody(body)
	if len(inputs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid token data found"})
		return
	}
	var ids []int64
	var errs []string
	for i, inp := range inputs {
		if inp.AccessToken == "" || inp.RefreshToken == "" {
			errs = append(errs, "entry "+strconv.Itoa(i)+": missing access_token or refresh_token")
			continue
		}
		if inp.Name == "" {
			inp.Name = "imported-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		if err := validateTokenInput(inp); err != nil {
			errs = append(errs, "entry "+strconv.Itoa(i)+" ("+inp.Name+"): token invalid - "+err.Error())
			continue
		}
		id, err := saveTokenInput(inp)
		if err != nil {
			errs = append(errs, "entry "+strconv.Itoa(i)+": "+err.Error())
		} else {
			ids = append(ids, id)
			kiro.TriggerQuotaUpdate(id)
		}
	}
	c.JSON(http.StatusOK, gin.H{"imported": len(ids), "ids": ids, "errors": errs})
}

func parseImportBody(body []byte) []tokenInput {
	// 1. rawTokenJSON 数组
	var rawArr []rawTokenJSON
	if err := json.Unmarshal(body, &rawArr); err == nil && len(rawArr) > 0 && rawArr[0].AccessToken != "" {
		result := make([]tokenInput, 0, len(rawArr))
		for i, r := range rawArr {
			name := r.AuthMethod
			if name == "" {
				name = "imported"
			}
			if len(rawArr) > 1 {
				name = name + "-" + strconv.Itoa(i+1)
			}
			result = append(result, r.toInput(name))
		}
		return result
	}
	// 2. 单个 rawTokenJSON
	var raw rawTokenJSON
	if err := json.Unmarshal(body, &raw); err == nil && raw.AccessToken != "" {
		name := raw.AuthMethod
		if name == "" {
			name = "imported"
		}
		return []tokenInput{raw.toInput(name)}
	}
	// 3. tokenInput 数组
	var inpArr []tokenInput
	if err := json.Unmarshal(body, &inpArr); err == nil && len(inpArr) > 0 && inpArr[0].AccessToken != "" {
		return inpArr
	}
	// 4. 单个 tokenInput
	var inp tokenInput
	if err := json.Unmarshal(body, &inp); err == nil && inp.AccessToken != "" {
		return []tokenInput{inp}
	}
	return nil
}

func deleteToken(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := db.DeleteToken(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func toggleEnabled(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := db.UpdateTokenEnabled(id, body.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func refreshToken(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	t, err := db.GetToken(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
		return
	}
	updated, err := kiro.Refresh(t)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"expires_at": updated.ExpiresAt})
}

func checkQuota(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	t, err := db.GetToken(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
		return
	}
	info, err := kiro.CheckQuota(t)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": info.Total, "used": info.Used, "remaining": info.Remaining})
}
