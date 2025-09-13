package token

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// TokenManager is a small helper to generate JWT access tokens and opaque refresh tokens.
// It does NOT perform token introspection — it only creates tokens and can verify JWT signatures.
// Refresh tokens are persisted by callers (we provide a helper to store hashed refresh tokens).

type TokenManager struct {
	jwtSecret []byte
	db        *sql.DB
}

func NewManager(jwtSecret string, db *sql.DB) *TokenManager {
	return &TokenManager{jwtSecret: []byte(jwtSecret), db: db}
}

// GenerateAccessToken creates a signed HS256 JWT with user_id and username, exp in ttlSeconds.
func (m *TokenManager) GenerateAccessToken(userID int64, username string, ttlSeconds int64) (string, error) {
	if len(m.jwtSecret) == 0 {
		return "", errors.New("jwt secret not configured")
	}
	claims := jwt.MapClaims{
		"sub":      fmt.Sprintf("%d", userID),
		"username": username,
		"exp":      time.Now().Add(time.Duration(ttlSeconds) * time.Second).Unix(),
		"iat":      time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// VerifyAccessToken verifies the token signature and returns claims map (or error).
func (m *TokenManager) VerifyAccessToken(tokenStr string) (jwt.MapClaims, error) {
	if len(m.jwtSecret) == 0 {
		return nil, errors.New("jwt secret not configured")
	}
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// GenerateRefreshToken creates an opaque token and returns (rawToken, hashedToken).
// The caller should persist hashedToken (sha256 hex) and return rawToken to the user only once.
func GenerateRefreshToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(h[:])
	return raw, hash, nil
}

// StoreRefreshToken persists hashed refresh token into refresh_tokens table.
// Assumes a table with columns (user_id, token_hash, created_at, expires_at, revoked).
func StoreRefreshToken(db *sql.DB, userID int64, tokenHash string, expiresAt time.Time) error {
	if db == nil {
		return errors.New("db is nil")
	}
	q := `INSERT INTO refresh_tokens (user_id, token_hash, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, 0)`
	_, err := db.Exec(q, userID, tokenHash, time.Now().UTC().Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano))
	return err
}
