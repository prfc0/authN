package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/prfc0/authN/internal/token"
)

type ctxKey string

const (
	ctxUserIDKey   ctxKey = "auth_user_id"
	ctxUsernameKey ctxKey = "auth_username"
)

type errResp struct {
	Error string `json:"error"`
}

func RequireAuth(tm *token.TokenManager) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authz := r.Header.Get("Authorization")
			if authz == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errResp{Error: "authorization_required"})
				return
			}

			parts := strings.Fields(authz)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errResp{Error: "invalid_authorization_header"})
				return
			}

			claims, err := tm.VerifyAccessToken(parts[1])
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errResp{Error: "invalid_token"})
				return
			}

			// put claims in context (minimal — just username if present)
			ctx := r.Context()
			if sub, ok := claims["sub"]; ok {
				ctx = context.WithValue(ctx, ctxUserIDKey, sub)
			}
			if u, ok := claims["username"]; ok {
				if s, ok := u.(string); ok {
					ctx = context.WithValue(ctx, ctxUsernameKey, s)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UsernameFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxUsernameKey)
	if s, ok := v.(string); ok {
		return s, true
	}
	return "", false
}

func UserIDFromContext(ctx context.Context) (interface{}, bool) {
	v := ctx.Value(ctxUserIDKey)
	return v, v != nil
}
