// Package gormstore is a passkey.Store on GORM, made for PostgreSQL (it also runs on SQLite, which
// its tests use).
//
// It keeps five tables of its own, all named passkey_*: users (the passkey identity of your app's
// users, by your user id), credentials, sessions, challenges and codes. Call Migrate once at start-up,
// or take the models into your own migrations.
package gormstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/ez-technologies/passkey"
)

// UserRow is a row of passkey_users.
type UserRow struct {
	ID          string `gorm:"primaryKey;size:191"`
	Handle      []byte `gorm:"uniqueIndex;not null"`
	Name        string `gorm:"not null"`
	DisplayName string `gorm:"not null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (UserRow) TableName() string { return "passkey_users" }

// CredentialRow is a row of passkey_credentials.
type CredentialRow struct {
	ID             []byte `gorm:"primaryKey"`
	UserID         string `gorm:"index;size:191;not null"`
	PublicKey      []byte `gorm:"not null"`
	SignCount      uint32 `gorm:"not null"`
	Transports     string `gorm:"not null"`
	AAGUID         []byte
	BackupEligible bool   `gorm:"not null"`
	BackupState    bool   `gorm:"not null"`
	Name           string `gorm:"not null"`
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

func (CredentialRow) TableName() string { return "passkey_credentials" }

// SessionRow is a row of passkey_sessions.
type SessionRow struct {
	ID           string `gorm:"primaryKey;size:64"`
	UserID       string `gorm:"index;size:191;not null"`
	CredentialID []byte
	CreatedAt    time.Time
	ExpiresAt    time.Time `gorm:"index"`
	LastActiveAt time.Time
	ConfirmedAt  time.Time
}

func (SessionRow) TableName() string { return "passkey_sessions" }

// ChallengeRow is a row of passkey_challenges.
type ChallengeRow struct {
	ID        string    `gorm:"primaryKey;size:64"`
	Kind      string    `gorm:"size:16;not null"`
	UserID    string    `gorm:"size:191"`
	Data      []byte    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"index"`
}

func (ChallengeRow) TableName() string { return "passkey_challenges" }

// CodeRow is a row of passkey_codes.
type CodeRow struct {
	Hash      string `gorm:"primaryKey;size:64"`
	UserID    string `gorm:"index;size:191;not null"`
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

func (CodeRow) TableName() string { return "passkey_codes" }

// Models are the tables of this store, for your own migration tool.
func Models() []any {
	return []any{&UserRow{}, &CredentialRow{}, &SessionRow{}, &ChallengeRow{}, &CodeRow{}}
}

// Store is a passkey.Store on a *gorm.DB.
type Store struct{ db *gorm.DB }

var _ passkey.Store = (*Store)(nil)

// New wraps db.
func New(db *gorm.DB) *Store { return &Store{db: db} }

// Migrate creates or updates the tables.
func (s *Store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(Models()...)
}

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return passkey.ErrNotFound
	}
	return err
}

func (s *Store) SaveUser(ctx context.Context, u *passkey.User) error {
	row := UserRow{ID: u.ID, Handle: u.Handle, Name: u.Name, DisplayName: u.DisplayName}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "display_name", "updated_at"}),
	}).Create(&row).Error
}

func toUser(r UserRow) *passkey.User {
	return &passkey.User{ID: r.ID, Handle: r.Handle, Name: r.Name, DisplayName: r.DisplayName}
}

func (s *Store) UserByID(ctx context.Context, id string) (*passkey.User, error) {
	var row UserRow
	if err := s.db.WithContext(ctx).Take(&row, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return toUser(row), nil
}

func (s *Store) UserByHandle(ctx context.Context, handle []byte) (*passkey.User, error) {
	if len(handle) == 0 {
		return nil, passkey.ErrNotFound
	}
	var row UserRow
	if err := s.db.WithContext(ctx).Take(&row, "handle = ?", handle).Error; err != nil {
		return nil, notFound(err)
	}
	return toUser(row), nil
}

func (s *Store) AddCredential(ctx context.Context, c *passkey.Credential) error {
	row := CredentialRow{
		ID: c.ID, UserID: c.UserID, PublicKey: c.PublicKey, SignCount: c.SignCount,
		Transports: strings.Join(c.Transports, ","), AAGUID: c.AAGUID,
		BackupEligible: c.BackupEligible, BackupState: c.BackupState, Name: c.Name,
		CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt,
	}
	return s.db.WithContext(ctx).Create(&row).Error
}

func (s *Store) Credentials(ctx context.Context, userID string) ([]passkey.Credential, error) {
	var rows []CredentialRow
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]passkey.Credential, 0, len(rows))
	for _, r := range rows {
		var transports []string
		if r.Transports != "" {
			transports = strings.Split(r.Transports, ",")
		}
		out = append(out, passkey.Credential{
			ID: r.ID, UserID: r.UserID, PublicKey: r.PublicKey, SignCount: r.SignCount, Transports: transports,
			AAGUID: r.AAGUID, BackupEligible: r.BackupEligible, BackupState: r.BackupState, Name: r.Name,
			CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt,
		})
	}
	return out, nil
}

func (s *Store) UpdateCredential(ctx context.Context, c *passkey.Credential) error {
	res := s.db.WithContext(ctx).Model(&CredentialRow{}).Where("id = ?", c.ID).Updates(map[string]any{
		"sign_count": c.SignCount, "backup_state": c.BackupState, "last_used_at": c.LastUsedAt,
	})
	if res.Error == nil && res.RowsAffected == 0 {
		return passkey.ErrNotFound
	}
	return res.Error
}

func (s *Store) DeleteCredential(ctx context.Context, userID string, id []byte) error {
	res := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&CredentialRow{})
	if res.Error == nil && res.RowsAffected == 0 {
		return passkey.ErrNotFound
	}
	return res.Error
}

func (s *Store) CreateSession(ctx context.Context, sess *passkey.Session) error {
	row := SessionRow{
		ID: sess.ID, UserID: sess.UserID, CredentialID: sess.CredentialID, CreatedAt: sess.CreatedAt,
		ExpiresAt: sess.ExpiresAt, LastActiveAt: sess.LastActiveAt, ConfirmedAt: sess.ConfirmedAt,
	}
	db := s.db.WithContext(ctx)
	// Ended sessions are cleared as new ones begin, so the table needs no sweeper.
	db.Where("expires_at < ?", sess.CreatedAt).Delete(&SessionRow{})
	return db.Create(&row).Error
}

func (s *Store) GetSession(ctx context.Context, id string) (*passkey.Session, error) {
	var r SessionRow
	if err := s.db.WithContext(ctx).Take(&r, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return &passkey.Session{
		ID: r.ID, UserID: r.UserID, CredentialID: r.CredentialID, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, LastActiveAt: r.LastActiveAt, ConfirmedAt: r.ConfirmedAt,
	}, nil
}

func (s *Store) TouchSession(ctx context.Context, sess *passkey.Session) error {
	res := s.db.WithContext(ctx).Model(&SessionRow{}).Where("id = ?", sess.ID).Updates(map[string]any{
		"last_active_at": sess.LastActiveAt, "confirmed_at": sess.ConfirmedAt,
	})
	if res.Error == nil && res.RowsAffected == 0 {
		return passkey.ErrNotFound
	}
	return res.Error
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&SessionRow{}, "id = ?", id).Error
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Delete(&SessionRow{}, "user_id = ?", userID).Error
}

func (s *Store) SaveChallenge(ctx context.Context, c *passkey.Challenge) error {
	db := s.db.WithContext(ctx)
	db.Where("expires_at < ?", time.Now()).Delete(&ChallengeRow{})
	return db.Create(&ChallengeRow{ID: c.ID, Kind: c.Kind, UserID: c.UserID, Data: c.Data, ExpiresAt: c.ExpiresAt}).Error
}

func (s *Store) TakeChallenge(ctx context.Context, id string) (*passkey.Challenge, error) {
	var rows []ChallengeRow
	// DELETE ... RETURNING: of two requests racing for one challenge, only one gets it.
	res := s.db.WithContext(ctx).Clauses(clause.Returning{}).Where("id = ?", id).Delete(&rows)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 || len(rows) == 0 {
		return nil, passkey.ErrNotFound
	}
	r := rows[0]
	return &passkey.Challenge{ID: r.ID, Kind: r.Kind, UserID: r.UserID, Data: r.Data, ExpiresAt: r.ExpiresAt}, nil
}

func (s *Store) CreateCode(ctx context.Context, c *passkey.Code) error {
	return s.db.WithContext(ctx).Create(&CodeRow{Hash: c.Hash, UserID: c.UserID, CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt}).Error
}

func (s *Store) RedeemCode(ctx context.Context, hash string, now time.Time) (*passkey.Code, error) {
	var rows []CodeRow
	res := s.db.WithContext(ctx).Model(&rows).Clauses(clause.Returning{}).
		Where("hash = ? AND used_at IS NULL AND expires_at > ?", hash, now).
		Update("used_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 || len(rows) == 0 {
		return nil, passkey.ErrNotFound
	}
	r := rows[0]
	return &passkey.Code{Hash: r.Hash, UserID: r.UserID, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt}, nil
}
