package server

import (
	"log"
	"net/http"
	"time"

	"github.com/prfc0/authN/internal/handlers"
	"github.com/prfc0/authN/internal/middleware"
	"github.com/prfc0/authN/internal/store"
	"github.com/prfc0/authN/internal/token"
)

type Server struct {
	srv *http.Server
}

func New(us store.UserStore, tm *token.TokenManager) *Server {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/auth/register", handlers.MakeRegisterHandler(us))
	mux.Handle("/api/v1/auth/login", handlers.MakeLoginHandler(us, tm))
	mux.Handle("/api/v1/auth/refresh", handlers.MakeRefreshHandler(us, tm))
	mux.Handle("/api/v1/backend", middleware.RequireAuth(tm)(handlers.MakeBackendHandler()))

	s := &http.Server{
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return &Server{srv: s}
}

func (s *Server) ListenAndServe(addr string) error {
	s.srv.Addr = addr
	return s.srv.ListenAndServe()
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
