package store

import (
	"context"
	"errors"
	"time"

	"github.com/prfc0/authN/internal/model"
)

var (
	// ErrUserExists is returned when trying to create a user with an existing username.
	ErrUserExists = errors.New("user already exists")
)

type UserStore interface {
	// CreateUser stores username and hashed password and returns new ID.
	CreateUser(ctx context.Context, username, passwordHash string) (int64, error)
	// GetUserByUsername returns user or (nil, nil) if not found.
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	StoreRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
	CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time, deviceInfo *string) (int64, error)
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error)
	MarkRefreshTokenRevokedAndSetReplacement(ctx context.Context, id, replacedBy int64) error
	RevokeAllRefreshTokensForUser(ctx context.Context, userID int64) error
}
