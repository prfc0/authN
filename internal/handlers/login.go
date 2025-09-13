package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/prfc0/authN/internal/store"
	"github.com/prfc0/authN/internal/token"
)

// LoginRequest matches the register request fields for username/password
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	UserID           int64  `json:"user_id"`
	AccessToken      string `json:"access_token"`
	AccessExpiresIn  int64  `json:"access_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// MakeLoginHandler returns an http.Handler that authenticates a user and issues tokens.
// - us: UserStore to lookup user and verify password
// - tm: TokenManager for creating JWT
// - db: *sql.DB where refresh tokens will be stored (StoreRefreshToken helper)
func MakeLoginHandler(us store.UserStore, tm *token.TokenManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "method_not_allowed"})
			return
		}

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_json"})
			return
		}
		req.Username = trim(req.Username)
		req.Password = trim(req.Password)
		if req.Username == "" || req.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "username_and_password_required"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		user, err := us.GetUserByUsername(ctx, req.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal_error"})
			return
		}
		if user == nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_credentials"})
			return
		}

		// verify password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_credentials"})
			return
		}

		// 1) create access token (JWT) — TTL 900s
		access, err := tm.GenerateAccessToken(user.ID, user.Username, 900)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "token_generation_failed"})
			return
		}

		// 2) create refresh token (opaque) — TTL 1 day
		raw, hash, err := token.GenerateRefreshToken()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "token_generation_failed"})
			return
		}
		expires := time.Now().Add(24 * time.Hour)
		if err := us.StoreRefreshToken(ctx, user.ID, hash, expires); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal_error"})
			return
		}

		resp := LoginResponse{
			UserID:           user.ID,
			AccessToken:      access,
			AccessExpiresIn:  900,
			RefreshToken:     raw,
			RefreshExpiresIn: 86400,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}

// small helper trim (replace with your existing helper in project)
func trim(s string) string { return s }
