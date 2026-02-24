package db

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type Token struct {
	ID                    int64     `json:"id"`
	Name                  string    `json:"name"`
	AuthMethod            string    `json:"auth_method"` // "social" or "builder-id"
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	ProfileArn            string    `json:"profile_arn"`
	ClientID              string    `json:"client_id"`
	ClientSecret          string    `json:"client_secret"`
	Region                string    `json:"region"`
	ExpiresAt             time.Time `json:"expires_at"`
	RegistrationExpiresAt time.Time `json:"registration_expires_at"`
	Enabled               bool      `json:"enabled"`
	LastUsedAt            *time.Time `json:"last_used_at"`
	CreatedAt             time.Time `json:"created_at"`
	// 配额信息（从 API 查询后缓存）
	QuotaTotal     int        `json:"quota_total"`
	QuotaUsed      int        `json:"quota_used"`
	QuotaCheckedAt *time.Time `json:"quota_checked_at"`
}

var DB *sql.DB

func Init(path string) error {
	var err error
	DB, err = sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	// 开启 WAL 模式，避免并发读写时 "database is locked" 错误
	if _, err := DB.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return err
	}
	return migrate()
}

func migrate() error {
	_, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			id                      INTEGER PRIMARY KEY AUTOINCREMENT,
			name                    TEXT NOT NULL,
			auth_method             TEXT NOT NULL,
			access_token            TEXT NOT NULL,
			refresh_token           TEXT NOT NULL,
			profile_arn             TEXT DEFAULT '',
			client_id               TEXT DEFAULT '',
			client_secret           TEXT DEFAULT '',
			region                  TEXT DEFAULT 'us-east-1',
			expires_at              DATETIME NOT NULL,
			registration_expires_at DATETIME,
			enabled                 INTEGER DEFAULT 1,
			last_used_at            DATETIME,
			created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
			quota_total             INTEGER DEFAULT 0,
			quota_used              INTEGER DEFAULT 0,
			quota_checked_at        DATETIME
		)
	`)
	return err
}

func ListTokens() ([]Token, error) {
	rows, err := DB.Query(`SELECT id, name, auth_method, access_token, refresh_token,
		profile_arn, client_id, client_secret, region, expires_at, registration_expires_at,
		enabled, last_used_at, created_at, quota_total, quota_used, quota_checked_at
		FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

func GetToken(id int64) (*Token, error) {
	row := DB.QueryRow(`SELECT id, name, auth_method, access_token, refresh_token,
		profile_arn, client_id, client_secret, region, expires_at, registration_expires_at,
		enabled, last_used_at, created_at, quota_total, quota_used, quota_checked_at
		FROM tokens WHERE id = ?`, id)
	t, err := scanToken(row)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// GetNextEligibleToken 轮询获取下一个可用 token，跳过剩余配额低于 minQuota 的（0 表示不限制）
func GetNextEligibleToken(afterID int64, minQuota int) (*Token, error) {
	const q = `SELECT id, name, auth_method, access_token, refresh_token,
		profile_arn, client_id, client_secret, region, expires_at, registration_expires_at,
		enabled, last_used_at, created_at, quota_total, quota_used, quota_checked_at
		FROM tokens WHERE enabled = 1 AND id > ?
		AND (? = 0 OR quota_total = 0 OR (quota_total - quota_used) >= ?)
		ORDER BY id ASC LIMIT 1`

	const qWrap = `SELECT id, name, auth_method, access_token, refresh_token,
		profile_arn, client_id, client_secret, region, expires_at, registration_expires_at,
		enabled, last_used_at, created_at, quota_total, quota_used, quota_checked_at
		FROM tokens WHERE enabled = 1
		AND (? = 0 OR quota_total = 0 OR (quota_total - quota_used) >= ?)
		ORDER BY id ASC LIMIT 1`

	row := DB.QueryRow(q, afterID, minQuota, minQuota)
	t, err := scanToken(row)
	if err == sql.ErrNoRows {
		row = DB.QueryRow(qWrap, minQuota, minQuota)
		t, err = scanToken(row)
	}
	if err == sql.ErrNoRows {
		// 所有 token 都低于最低配额，降级：忽略配额限制取第一个可用的
		row = DB.QueryRow(`SELECT id, name, auth_method, access_token, refresh_token,
			profile_arn, client_id, client_secret, region, expires_at, registration_expires_at,
			enabled, last_used_at, created_at, quota_total, quota_used, quota_checked_at
			FROM tokens WHERE enabled = 1 ORDER BY id ASC LIMIT 1`)
		t, err = scanToken(row)
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// GetNextEnabledToken 保留兼容，内部调用 GetNextEligibleToken
func GetNextEnabledToken(afterID int64) (*Token, error) {
	return GetNextEligibleToken(afterID, 0)
}

func CreateToken(t *Token) (int64, error) {
	res, err := DB.Exec(`INSERT INTO tokens
		(name, auth_method, access_token, refresh_token, profile_arn, client_id, client_secret,
		region, expires_at, registration_expires_at, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.Name, t.AuthMethod, t.AccessToken, t.RefreshToken, t.ProfileArn,
		t.ClientID, t.ClientSecret, t.Region, t.ExpiresAt, t.RegistrationExpiresAt, t.Enabled)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateTokenCredentials(id int64, accessToken, refreshToken string, expiresAt time.Time) error {
	_, err := DB.Exec(`UPDATE tokens SET access_token=?, refresh_token=?, expires_at=? WHERE id=?`,
		accessToken, refreshToken, expiresAt, id)
	return err
}

func UpdateTokenEnabled(id int64, enabled bool) error {
	_, err := DB.Exec(`UPDATE tokens SET enabled=? WHERE id=?`, enabled, id)
	return err
}

func UpdateTokenLastUsed(id int64) error {
	_, err := DB.Exec(`UPDATE tokens SET last_used_at=? WHERE id=?`, time.Now(), id)
	return err
}

func UpdateTokenQuota(id int64, total, used int) error {
	now := time.Now()
	_, err := DB.Exec(`UPDATE tokens SET quota_total=?, quota_used=?, quota_checked_at=? WHERE id=?`,
		total, used, now, id)
	return err
}

func DeleteToken(id int64) error {
	_, err := DB.Exec(`DELETE FROM tokens WHERE id=?`, id)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanToken(s scanner) (Token, error) {
	var t Token
	var regExpAt sql.NullTime
	var lastUsedAt sql.NullTime
	var quotaCheckedAt sql.NullTime
	err := s.Scan(
		&t.ID, &t.Name, &t.AuthMethod, &t.AccessToken, &t.RefreshToken,
		&t.ProfileArn, &t.ClientID, &t.ClientSecret, &t.Region,
		&t.ExpiresAt, &regExpAt, &t.Enabled, &lastUsedAt, &t.CreatedAt,
		&t.QuotaTotal, &t.QuotaUsed, &quotaCheckedAt,
	)
	if regExpAt.Valid {
		t.RegistrationExpiresAt = regExpAt.Time
	}
	if lastUsedAt.Valid {
		t.LastUsedAt = &lastUsedAt.Time
	}
	if quotaCheckedAt.Valid {
		t.QuotaCheckedAt = &quotaCheckedAt.Time
	}
	return t, err
}
