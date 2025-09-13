package main

import (
	"log"
	"os"

	"database/sql"

	"github.com/prfc0/authN/internal/server"
	"github.com/prfc0/authN/internal/store/sqlite"
	"github.com/prfc0/authN/internal/token"
	_ "modernc.org/sqlite"
)

func main() {
	dbPath := os.Getenv("AUTH_DB_PATH")
	if dbPath == "" {
		dbPath = "./auth.db"
	}

	db, err := sql.Open("sqlite", "file:"+dbPath+"?_foreign_keys=1&_busy_timeout=5000")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := sqlite.EnsureUsersTable(db); err != nil {
		log.Fatalf("users migrations failed: %v", err)
	}
	if err := sqlite.EnsureRefreshTokensTable(db); err != nil {
		log.Fatalf("refresh_tokens migration failed: %v", err)
	}

	store := sqlite.NewSQLiteUserStore(db)
	jwtSecret := os.Getenv("AUTH_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super_secret_change_me"
		// log.Fatal("AUTH_JWT_SECRET not set")
	}
	tm := token.NewManager(jwtSecret, db)
	srv := server.New(store, tm)
	log.Println("listening on :8080")
	if err := srv.ListenAndServe(":8080"); err != nil {
		log.Fatalf("server: %v", err)
	}
}
