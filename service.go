// Package passkey is passwordless sign-in with passkeys (WebAuthn) for Go web apps.
//
// A Service runs the WebAuthn ceremonies on top of github.com/go-webauthn/webauthn, keeps signed-in
// browsers in an HttpOnly cookie, and applies a step-up policy that is configuration: an idle
// interval after which the person confirms with their passkey again, and a list of sensitive
// actions that always need a recent confirmation. Data goes through the Store interface, which
// your app implements or takes from the memstore and gormstore packages.
//
// An app that keeps its own sessions, users and one-time codes uses Ceremonies instead: only the
// WebAuthn ceremonies, on the smaller CeremonyStore.
//
// The Service has no HTTP routes of its own; the ginpasskey package mounts them on Gin, and the
// methods here are what any other router would call.
package passkey

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/ez-technologies/apperr"
)

// Service is passkey sign-in for one app. It is safe for concurrent use.
type Service struct {
	cfg    Config
	store  Store
	cer    *Ceremonies
	policy atomic.Pointer[policy]
}

// New builds a Service.
func New(cfg Config, store Store) (*Service, error) {
	cer, err := NewCeremonies(cfg, store)
	if err != nil {
		return nil, err
	}
	p, err := newPolicy(Policy{ReconfirmAfter: cer.cfg.ReconfirmAfter, SensitiveActions: cer.cfg.SensitiveActions, FreshFor: cer.cfg.FreshFor}, cer.cfg.TouchEvery)
	if err != nil {
		return nil, err
	}
	svc := &Service{cfg: cer.cfg, store: store, cer: cer}
	svc.policy.Store(p)
	return svc, nil
}

// Config is the configuration in use, defaults filled in. Its policy fields (ReconfirmAfter,
// SensitiveActions, FreshFor) and TouchEvery are those of the current Policy.
func (s *Service) Config() Config {
	c, p := s.cfg, s.policy.Load()
	c.ReconfirmAfter, c.SensitiveActions, c.FreshFor = p.ReconfirmAfter, slices.Clone(p.SensitiveActions), p.FreshFor
	c.TouchEvery = p.touchEvery
	return c
}

// Store is the store the Service was built with.
func (s *Service) Store() Store { return s.store }

// BeginRegistration starts adding a passkey to u, an existing user of your app who is signed in
// (u.ID set; Name and DisplayName update the stored ones when set). Finish it with
// FinishRegistration, passing the id of the user whose session finishes it. It returns the
// challenge id to send back with the finish, and the options for the browser.
//
// For a new user, with nobody signed in, use BeginSignUp instead.
func (s *Service) BeginRegistration(ctx context.Context, u User) (challengeID string, options Options, err error) {
	return s.beginRegistration(ctx, u, kindAddPasskey)
}

// BeginSignUp starts making the first passkey of a new user (u.ID, u.Name and u.DisplayName set;
// Handle is filled in by the library), while nobody is signed in. Finish it with FinishSignUp.
//
// u must be a NEW user: an existing user's id would let whoever calls this add a passkey to that
// account. To add a passkey to an existing account, sign the person in and use BeginRegistration.
func (s *Service) BeginSignUp(ctx context.Context, u User) (challengeID string, options Options, err error) {
	return s.beginRegistration(ctx, u, kindSignUp)
}

func (s *Service) beginRegistration(ctx context.Context, u User, kind string) (string, Options, error) {
	if strings.TrimSpace(u.ID) == "" {
		return "", nil, apperr.Wrap(CodeBadRequest, fmt.Errorf("a user id is required: %w", apperr.ErrInvalidInput))
	}
	user, err := s.ensureUser(ctx, u)
	if err != nil {
		return "", nil, err
	}
	return s.cer.beginRegistration(ctx, user, kind)
}

func (s *Service) ensureUser(ctx context.Context, u User) (*User, error) {
	existing, err := s.store.UserByID(ctx, u.ID)
	switch {
	case err == nil:
		changed := false
		if u.Name != "" && u.Name != existing.Name {
			existing.Name, changed = u.Name, true
		}
		if u.DisplayName != "" && u.DisplayName != existing.DisplayName {
			existing.DisplayName, changed = u.DisplayName, true
		}
		if changed {
			if err := s.store.SaveUser(ctx, existing); err != nil {
				return nil, err
			}
		}
		return existing, nil
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return nil, err
	}
	user := &User{ID: u.ID, Handle: handle, Name: u.Name, DisplayName: u.DisplayName}
	if user.Name == "" {
		user.Name = u.ID
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Name
	}
	return user, s.store.SaveUser(ctx, user)
}

// FinishRegistration finishes a BeginRegistration: it checks what the device made (response is
// the JSON from startRegistration) and stores the new credential under name.
//
// userID is the user of the session that finishes it, and must be the user the registration began
// for. Pass "" when there is no session: the answer is then CodeSessionRequired, never a sign-up,
// and the challenge is used up. A challenge of BeginSignUp is refused (CodeChallengeExpired).
func (s *Service) FinishRegistration(ctx context.Context, challengeID, userID string, response []byte, name string) (*Credential, error) {
	return s.cer.FinishRegistration(ctx, challengeID, userID, response, NewCredential{Name: name})
}

// FinishSignUp finishes a BeginSignUp, with nobody signed in: the challenge id (a secret only the
// browser that began holds) is what ties the two steps together. The new credential's UserID says
// who it is for; start a session for them with StartSession.
//
// A challenge of BeginRegistration (a passkey for a signed-in user) is never turned into a
// sign-up: it is answered with CodeSessionRequired, so the person signs in again.
func (s *Service) FinishSignUp(ctx context.Context, challengeID string, response []byte, name string) (*Credential, error) {
	ch, err := s.store.TakeChallenge(ctx, challengeID)
	if errors.Is(err, ErrNotFound) {
		return nil, errChallenge()
	}
	if err != nil {
		return nil, err
	}
	if ch.Kind == kindAddPasskey {
		return nil, errSessionRequired()
	}
	_, data, err := s.cer.checkChallenge(ch, kindSignUp)
	if err != nil {
		return nil, err
	}
	return s.cer.finishRegistration(ctx, ch.UserID, data, response, NewCredential{Name: name})
}

// BeginLogin starts a sign-in with nobody named: the device answers with who it is.
func (s *Service) BeginLogin(ctx context.Context) (challengeID string, options Options, err error) {
	return s.cer.BeginLogin(ctx)
}

// FinishLogin checks the device's signature (response is the JSON from startAuthentication) and
// returns the user and the credential used. Every failure is CodeRejected, whatever the reason.
func (s *Service) FinishLogin(ctx context.Context, challengeID string, response []byte) (*User, *Credential, error) {
	return s.cer.FinishLogin(ctx, challengeID, response)
}

// BeginConfirm starts a confirmation for the user of a session: the options name only that user's
// passkeys, so the device goes straight to the fingerprint or face prompt.
func (s *Service) BeginConfirm(ctx context.Context, sess *Session) (challengeID string, options Options, err error) {
	if sess == nil {
		return "", nil, errSessionRequired()
	}
	return s.cer.BeginConfirm(ctx, sess.UserID)
}

// FinishConfirm checks the confirmation and marks the session confirmed and active now. It also
// ends an idle lock.
func (s *Service) FinishConfirm(ctx context.Context, sess *Session, challengeID string, response []byte) error {
	if sess == nil {
		return errSessionRequired()
	}
	if _, err := s.cer.FinishConfirm(ctx, sess.UserID, challengeID, response); err != nil {
		return err
	}
	now := s.cfg.Now()
	sess.LastActiveAt, sess.ConfirmedAt = now, now
	return s.store.TouchSession(ctx, sess)
}

// Credentials lists a user's passkeys.
func (s *Service) Credentials(ctx context.Context, userID string) ([]Credential, error) {
	return s.store.Credentials(ctx, userID)
}

// RemoveCredential deletes one passkey of a user. Sessions already signed in stay; call
// SignOutEverywhere as well to end them.
func (s *Service) RemoveCredential(ctx context.Context, userID string, credentialID []byte) error {
	return s.store.DeleteCredential(ctx, userID, credentialID)
}
