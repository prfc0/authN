package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/prfc0/authN/internal/middleware"
)

// MakeBackendHandler returns a minimal protected endpoint that assumes
// the middleware has injected "username" into the context.
func MakeBackendHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, _ := middleware.UsernameFromContext(r.Context())

		// Minimal demo: assume username is present.
		if username == "" {
			username = "user"
		}

		resp := map[string]string{
			"message": "Hello " + username + ", from backend!",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})
}
