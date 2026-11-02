package passkey

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is what a Store returns when the thing asked for does not exist.
var ErrNotFound = errors.New("passkey: not found")

// User is the passkey identity of one person in your app.
//
// ID is your app's own user id, as a string. Handle is the WebAuthn user handle: random bytes the
// library makes once per user and stores on the device with the passkey, so a sign-in can find the
// person without them typing anything. Name and DisplayName are what the device shows in its
// account chooser.
type User struct {
	ID          string
	Handle      []byte
	Name        string
	DisplayName string
}

// Credential is one passkey of a user.
type Credential struct {
	ID             []byte
	UserID         string
	PublicKey      []byte
	SignCount      uint32
	Transports     []string
	AAGUID         []byte
	BackupEligible bool
	BackupState    bool
	// Name is a label for the person ("Laptop", "Phone").
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// Session is a signed-in browser.
//
// ID is the SHA-256 of the cookie token, in hex: the token itself is never stored, so a copy of the
// database cannot be used to sign in.
type Session struct {
	ID     string
	UserID string
	// CredentialID is the passkey that started the session; empty for a session started with a
	// one-time code.
	CredentialID []byte
	CreatedAt    time.Time
	ExpiresAt    time.Time
	// LastActiveAt is the last time the session was used. A session idle for longer than
	// Config.ReconfirmAfter needs a passkey confirmation before it is used again.
	LastActiveAt time.Time
	// ConfirmedAt is the last time the person proved it was them (sign-in or confirmation).
	ConfirmedAt time.Time
}

// Challenge is the server side of a ceremony between its begin and its finish.
type Challenge struct {
	ID string
	// Kind is "register", "login" or "confirm".
	Kind string
	// UserID is set when the ceremony belongs to a known user.
	UserID    string
	Data      []byte
	ExpiresAt time.Time
}

// Code is a one-time code, stored as the SHA-256 of the code in hex.
type Code struct {
	Hash      string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// Store is where the library keeps its data. Implement it on your own database, or use the
// memstore or gormstore packages. The storetest package checks an implementation.
//
// Methods that look something up return ErrNotFound when it does not exist.
type Store interface {
	// SaveUser creates or updates a user, keyed by ID.
	SaveUser(ctx context.Context, u *User) error
	UserByID(ctx context.Context, id string) (*User, error)
	UserByHandle(ctx context.Context, handle []byte) (*User, error)

	AddCredential(ctx context.Context, c *Credential) error
	// Credentials lists a user's credentials, oldest first; none is an empty list, not an error.
	Credentials(ctx context.Context, userID string) ([]Credential, error)
	// UpdateCredential writes SignCount, BackupState and LastUsedAt of the credential with c.ID.
	UpdateCredential(ctx context.Context, c *Credential) error
	DeleteCredential(ctx context.Context, userID string, credentialID []byte) error

	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	// TouchSession writes LastActiveAt and ConfirmedAt of the session with s.ID.
	TouchSession(ctx context.Context, s *Session) error
	DeleteSession(ctx context.Context, id string) error
	// DeleteUserSessions ends every session of a user.
	DeleteUserSessions(ctx context.Context, userID string) error

	SaveChallenge(ctx context.Context, c *Challenge) error
	// TakeChallenge returns a challenge and removes it, in one step: a challenge works once.
	TakeChallenge(ctx context.Context, id string) (*Challenge, error)

	CreateCode(ctx context.Context, c *Code) error
	// RedeemCode marks the code with this hash used at now and returns it, in one step, only if it
	// is unused and has not expired at now. Otherwise it returns ErrNotFound.
	RedeemCode(ctx context.Context, hash string, now time.Time) (*Code, error)
}
