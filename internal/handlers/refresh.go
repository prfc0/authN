package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/prfc0/authN/internal/store"
	"github.com/prfc0/authN/internal/token"
)

// RefreshRequest expects { "refresh_token": "<raw>" }
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse returns new access + refresh tokens
type RefreshResponse struct {
	UserID           int64  `json:"user_id"`
	AccessToken      string `json:"access_token"`
	AccessExpiresIn  int64  `json:"access_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// MakeRefreshHandler creates handler that rotates refresh tokens.
func MakeRefreshHandler(us store.UserStore, tm *token.TokenManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "method_not_allowed"})
			return
		}

		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_json"})
			return
		}
		if req.RefreshToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "refresh_token_required"})
			return
		}

		// hash incoming token
		h := sha256.Sum256([]byte(req.RefreshToken))
		hashHex := hex.EncodeToString(h[:])

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		rt, err := us.GetRefreshTokenByHash(ctx, hashHex)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal_error"})
			return
		}
		if rt == nil {
			// token unknown
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_refresh_token"})
			return
		}

		// if token is already revoked -> reuse detected => revoke all and fail
		if rt.Revoked {
			_ = us.RevokeAllRefreshTokensForUser(ctx, rt.UserID)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_refresh_token"})
			return
		}

		// if expired
		if rt.ExpiresAt.Before(time.Now()) {
			_ = us.MarkRefreshTokenRevokedAndSetReplacement(ctx, rt.ID, 0)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "refresh_token_expired"})
			return
		}

		// all good -> rotate: create new refresh token
		newRaw, newHash, err := token.GenerateRefreshToken()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "token_generation_failed"})
			return
		}
		newExpires := time.Now().Add(24 * time.Hour)
		newID, err := us.CreateRefreshToken(ctx, rt.UserID, newHash, newExpires, nil)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal_error"})
			return
		}

		// mark old revoked and set replacement
		if err := us.MarkRefreshTokenRevokedAndSetReplacement(ctx, rt.ID, newID); err != nil {
			// best-effort: try to revoke the new token to avoid orphan; but return error for now.
			_ = us.RevokeAllRefreshTokensForUser(ctx, rt.UserID)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal_error"})
			return
		}

		// create a new access token (JWT)
		accessToken, err := tm.GenerateAccessToken(rt.UserID, "", 900) // username optional here
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "token_generation_failed"})
			return
		}

		resp := RefreshResponse{
			UserID:           rt.UserID,
			AccessToken:      accessToken,
			AccessExpiresIn:  900,
			RefreshToken:     newRaw,
			RefreshExpiresIn: 86400,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}
