// Package memstore is a passkey.Store kept in memory: for tests, demos and single-process apps
// that do not mind signing everyone out on restart.
package memstore

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/ez-technologies/passkey"
)

// Store is an in-memory passkey.Store. The zero value is not ready; use New.
type Store struct {
	mu         sync.Mutex
	users      map[string]passkey.User
	creds      []passkey.Credential
	sessions   map[string]passkey.Session
	challenges map[string]passkey.Challenge
	codes      map[string]passkey.Code
}

var _ passkey.Store = (*Store)(nil)

// New makes an empty store.
func New() *Store {
	return &Store{
		users:      map[string]passkey.User{},
		sessions:   map[string]passkey.Session{},
		challenges: map[string]passkey.Challenge{},
		codes:      map[string]passkey.Code{},
	}
}

func clone(b []byte) []byte { return bytes.Clone(b) }

func cloneCred(c passkey.Credential) passkey.Credential {
	c.ID, c.PublicKey, c.AAGUID = clone(c.ID), clone(c.PublicKey), clone(c.AAGUID)
	c.Transports = slices.Clone(c.Transports)
	return c
}

func (s *Store) SaveUser(_ context.Context, u *passkey.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *u
	cp.Handle = clone(u.Handle)
	s.users[u.ID] = cp
	return nil
}

func (s *Store) UserByID(_ context.Context, id string) (*passkey.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, passkey.ErrNotFound
	}
	u.Handle = clone(u.Handle)
	return &u, nil
}

func (s *Store) UserByHandle(_ context.Context, handle []byte) (*passkey.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if len(handle) > 0 && bytes.Equal(u.Handle, handle) {
			u.Handle = clone(u.Handle)
			return &u, nil
		}
	}
	return nil, passkey.ErrNotFound
}

func (s *Store) AddCredential(_ context.Context, c *passkey.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds = append(s.creds, cloneCred(*c))
	return nil
}

func (s *Store) Credentials(_ context.Context, userID string) ([]passkey.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []passkey.Credential{}
	for _, c := range s.creds {
		if c.UserID == userID {
			out = append(out, cloneCred(c))
		}
	}
	return out, nil
}

func (s *Store) UpdateCredential(_ context.Context, c *passkey.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.creds {
		if bytes.Equal(s.creds[i].ID, c.ID) {
			s.creds[i].SignCount, s.creds[i].BackupState, s.creds[i].LastUsedAt = c.SignCount, c.BackupState, c.LastUsedAt
			return nil
		}
	}
	return passkey.ErrNotFound
}

func (s *Store) DeleteCredential(_ context.Context, userID string, id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.creds, func(c passkey.Credential) bool { return c.UserID == userID && bytes.Equal(c.ID, id) })
	if i < 0 {
		return passkey.ErrNotFound
	}
	s.creds = slices.Delete(s.creds, i, i+1)
	return nil
}

func (s *Store) CreateSession(_ context.Context, sess *passkey.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	cp.CredentialID = clone(sess.CredentialID)
	s.sessions[sess.ID] = cp
	return nil
}

func (s *Store) GetSession(_ context.Context, id string) (*passkey.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, passkey.ErrNotFound
	}
	sess.CredentialID = clone(sess.CredentialID)
	return &sess, nil
}

func (s *Store) TouchSession(_ context.Context, sess *passkey.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.sessions[sess.ID]
	if !ok {
		return passkey.ErrNotFound
	}
	cur.LastActiveAt, cur.ConfirmedAt = sess.LastActiveAt, sess.ConfirmedAt
	s.sessions[sess.ID] = cur
	return nil
}

func (s *Store) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *Store) DeleteUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *Store) SaveChallenge(_ context.Context, c *passkey.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Expired ones are dropped as new ones come, so nothing needs a sweeper.
	now := time.Now()
	for id, ch := range s.challenges {
		if ch.ExpiresAt.Before(now) {
			delete(s.challenges, id)
		}
	}
	cp := *c
	cp.Data = clone(c.Data)
	s.challenges[c.ID] = cp
	return nil
}

func (s *Store) TakeChallenge(_ context.Context, id string) (*passkey.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.challenges[id]
	if !ok {
		return nil, passkey.ErrNotFound
	}
	delete(s.challenges, id)
	return &ch, nil
}

func (s *Store) CreateCode(_ context.Context, c *passkey.Code) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[c.Hash] = *c
	return nil
}

func (s *Store) RedeemCode(_ context.Context, hash string, now time.Time) (*passkey.Code, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[hash]
	if !ok || c.UsedAt != nil || !now.Before(c.ExpiresAt) {
		return nil, passkey.ErrNotFound
	}
	used := now
	c.UsedAt = &used
	s.codes[hash] = c
	return &c, nil
}
