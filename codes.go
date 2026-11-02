package passkey

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"time"
)

// codeAlphabet has no 0/O, 1/I/L or U: easy to read aloud and to type on a phone.
const codeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

// CreateCode makes a one-time code for u (ID, Name, DisplayName as in BeginRegistration), a user whose device cannot make a passkey, or who lost
// theirs. It lasts ttl and works once. Only its hash is stored: give the returned code to the
// person (it is shown in groups of five, such as "K7QMT-9XPRW"; dashes and case do not matter when
// it is typed back).
//
// Who may create a code for whom is your app's decision; consider making it a sensitive action.
func (s *Service) CreateCode(ctx context.Context, u User, ttl time.Duration) (code string, expiresAt time.Time, err error) {
	if u.ID == "" || ttl <= 0 {
		return "", time.Time{}, errors.New("passkey: CreateCode needs a user id and a positive ttl")
	}
	// The user may have no passkey yet (a code is often how they get their first one).
	if _, err := s.ensureUser(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, s.cfg.CodeLength)
	for i := range raw {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeAlphabet))))
		if err != nil {
			return "", time.Time{}, err
		}
		raw[i] = codeAlphabet[n.Int64()]
	}
	now := s.cfg.Now()
	c := &Code{Hash: hashOf(string(raw)), UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := s.store.CreateCode(ctx, c); err != nil {
		return "", time.Time{}, err
	}
	return group(string(raw)), c.ExpiresAt, nil
}

func group(raw string) string {
	var b strings.Builder
	for i, r := range raw {
		if i > 0 && i%5 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeCode is a typed code the way it was made: upper case, no spaces or dashes.
func NormalizeCode(typed string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(typed) {
		if r != '-' && r != ' ' && r != '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RedeemCode uses a one-time code and returns whose it was. A wrong, used or expired code is
// CodeInvalidCode. Start a session with StartSession(ctx, w, user.ID, nil) to sign the person in,
// then let them register a passkey.
//
// Codes are short enough to type, so put a rate limit in front of the route that calls this.
func (s *Service) RedeemCode(ctx context.Context, code string) (*User, error) {
	c, err := s.store.RedeemCode(ctx, hashOf(NormalizeCode(code)), s.cfg.Now())
	if errors.Is(err, ErrNotFound) {
		return nil, errInvalidCode()
	}
	if err != nil {
		return nil, err
	}
	u, err := s.store.UserByID(ctx, c.UserID)
	if errors.Is(err, ErrNotFound) {
		return nil, errInvalidCode()
	}
	return u, err
}
