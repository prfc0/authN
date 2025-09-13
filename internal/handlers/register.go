package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/prfc0/authN/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ErrorResp struct {
	Error string `json:"error"`
}

type RegisterResp struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
}

func MakeRegisterHandler(us store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(ErrorResp{Error: "method_not_allowed"})
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResp{Error: "invalid_json"})
			return
		}
		req.Username = trim(req.Username)
		req.Password = trim(req.Password)
		if req.Username == "" || req.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResp{Error: "username_and_password_required"})
			return
		}

		// check exist
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		existing, err := us.GetUserByUsername(ctx, req.Username)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		if existing != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResp{Error: "user_already_exists"})
			return
		}

		// hash
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}

		id, err := us.CreateUser(ctx, req.Username, string(hash))
		if err != nil {
			if err == store.ErrUserExists { // if store returns the sentinel
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(ErrorResp{Error: "user_already_exists"})
				return
			}
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(RegisterResp{UserID: id, Username: req.Username})
	}
}
