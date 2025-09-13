package model

import "time"

// RefreshToken represents a persisted refresh token row.
type RefreshToken struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	TokenHash  string    `json:"token_hash"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Revoked    bool      `json:"revoked"`
	ReplacedBy *int64    `json:"replaced_by,omitempty"`
	DeviceInfo *string   `json:"device_info,omitempty"`
}
