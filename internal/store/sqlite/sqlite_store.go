package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/prfc0/authN/internal/model"
	"github.com/prfc0/authN/internal/store"
)

type SQLiteUserStore struct {
	db *sql.DB
}

func NewSQLiteUserStore(db *sql.DB) store.UserStore {
	return &SQLiteUserStore{db: db}
}

func EnsureUsersTable(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`
	_, err := db.Exec(schema)
	return err
}

func EnsureRefreshTokensTable(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS refresh_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	revoked INTEGER NOT NULL DEFAULT 0,
  replaced_by INTEGER NULL,
  device_info TEXT NULL,
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`
	_, err := db.Exec(schema)
	return err
}

func (s *SQLiteUserStore) CreateUser(ctx context.Context, username, passwordHash string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, passwordHash, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		// map sqlite unique constraint to a sentinel error (caller can inspect)
		if isUniqueConstraintErr(err) {
			return 0, store.ErrUserExists
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLiteUserStore) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at FROM users WHERE username = ?`, username)
	var u model.User
	var createdAt string
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		u.CreatedAt = t
	}
	return &u, nil
}

func (s *SQLiteUserStore) StoreRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens(user_id, token_hash, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, 0)`,
		userID, tokenHash, time.Now().UTC().Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano))
	return err
}

// CreateRefreshToken inserts a new refresh token row and returns its id.
func (s *SQLiteUserStore) CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time, deviceInfo *string) (int64, error) {
	q := `INSERT INTO refresh_tokens (user_id, token_hash, created_at, expires_at, revoked, device_info) VALUES (?, ?, ?, ?, 0, ?)`
	res, err := s.db.ExecContext(ctx, q, userID, tokenHash, time.Now().UTC().Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano), deviceInfo)
	if err != nil {
		// Unique constraint on token_hash -> treat as error
		return 0, err
	}
	return res.LastInsertId()
}

// GetRefreshTokenByHash returns the refresh token row or nil if not found.
func (s *SQLiteUserStore) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, token_hash, created_at, expires_at, revoked, replaced_by, device_info FROM refresh_tokens WHERE token_hash = ?`, tokenHash)
	var rt model.RefreshToken
	var createdAtStr, expiresAtStr string
	var revokedInt int
	var replacedBy sql.NullInt64
	var deviceInfo sql.NullString

	if err := row.Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &createdAtStr, &expiresAtStr, &revokedInt, &replacedBy, &deviceInfo); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rt.Revoked = revokedInt != 0
	if replacedBy.Valid {
		rid := replacedBy.Int64
		rt.ReplacedBy = &rid
	}
	if deviceInfo.Valid {
		d := deviceInfo.String
		rt.DeviceInfo = &d
	}
	if t, err := time.Parse(time.RFC3339Nano, createdAtStr); err == nil {
		rt.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, expiresAtStr); err == nil {
		rt.ExpiresAt = t
	}
	return &rt, nil
}

// MarkRefreshTokenRevokedAndSetReplacement marks token id as revoked and sets replaced_by = replacedBy.
func (s *SQLiteUserStore) MarkRefreshTokenRevokedAndSetReplacement(ctx context.Context, id, replacedBy int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = 1, replaced_by = ? WHERE id = ?`, replacedBy, id)
	return err
}

// RevokeAllRefreshTokensForUser sets revoked=1 for all tokens of user.
func (s *SQLiteUserStore) RevokeAllRefreshTokensForUser(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	return err
}

func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	// modernc sqlite error contains text "UNIQUE constraint failed"
	return contains(err.Error(), "UNIQUE constraint failed")
}

func contains(s, sub string) bool {
	return indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	n, sn := len(s), len(sub)
	if sn == 0 {
		return 0
	}
	for i := 0; i+sn <= n; i++ {
		if s[i:i+sn] == sub {
			return i
		}
	}
	return -1
}
