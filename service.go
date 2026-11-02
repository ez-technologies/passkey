// Package passkey is passwordless sign-in with passkeys (WebAuthn) for Go web apps.
//
// A Service runs the WebAuthn ceremonies on top of github.com/go-webauthn/webauthn, keeps signed-in
// browsers in an HttpOnly cookie, and applies a step-up policy that is configuration: an idle
// interval after which the person confirms with their passkey again, and a list of sensitive
// actions that always need a recent confirmation. Data goes through the Store interface, which
// your app implements or takes from the memstore and gormstore packages.
//
// The Service has no HTTP routes of its own; the ginpasskey package mounts them on Gin, and the
// methods here are what any other router would call.
package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ez-technologies/apperr"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Service is passkey sign-in for one app. It is safe for concurrent use.
type Service struct {
	cfg   Config
	store Store
	web   *webauthn.WebAuthn
}

// New builds a Service.
func New(cfg Config, store Store) (*Service, error) {
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("passkey: a Store is required")
	}
	web, err := webauthn.New(&webauthn.Config{
		RPID: c.RPID, RPDisplayName: c.RPName, RPOrigins: c.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// A discoverable credential: the device knows who the person is, so sign-in needs
			// nothing typed. The person proves they are there (fingerprint, face or PIN).
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: c.ChallengeTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: c.ChallengeTimeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Service{cfg: c, store: store, web: web}, nil
}

// Config is the configuration in use, defaults filled in.
func (s *Service) Config() Config { return s.cfg }

// Store is the store the Service was built with.
func (s *Service) Store() Store { return s.store }

// Options are the WebAuthn options a begin step hands to the browser, as JSON. Pass them to
// startRegistration / startAuthentication of @simplewebauthn/browser as optionsJSON.
type Options = json.RawMessage

// webUser is what go-webauthn needs to know about a person.
type webUser struct {
	u     *User
	creds []Credential
}

func (w webUser) WebAuthnID() []byte          { return w.u.Handle }
func (w webUser) WebAuthnName() string        { return w.u.Name }
func (w webUser) WebAuthnDisplayName() string { return w.u.DisplayName }
func (w webUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(w.creds))
	for _, c := range w.creds {
		out = append(out, toWebAuthn(c))
	}
	return out
}

func toWebAuthn(c Credential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID: c.ID, PublicKey: c.PublicKey, Transport: transports,
		Flags: webauthn.CredentialFlags{
			UserPresent: true, UserVerified: true, BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		},
		Authenticator: webauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount},
	}
}

func (s *Service) loadUser(ctx context.Context, u *User) (*webUser, error) {
	creds, err := s.store.Credentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return &webUser{u: u, creds: creds}, nil
}

func (s *Service) saveChallenge(ctx context.Context, kind, userID string, data *webauthn.SessionData) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	id, err := randomToken(18)
	if err != nil {
		return "", err
	}
	ch := &Challenge{ID: id, Kind: kind, UserID: userID, Data: raw, ExpiresAt: s.cfg.Now().Add(s.cfg.ChallengeTimeout)}
	return id, s.store.SaveChallenge(ctx, ch)
}

func (s *Service) takeChallenge(ctx context.Context, id, kind string) (*Challenge, *webauthn.SessionData, error) {
	ch, err := s.store.TakeChallenge(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, errChallenge()
	}
	if err != nil {
		return nil, nil, err
	}
	return s.checkChallenge(ch, kind)
}

// checkChallenge checks a taken challenge's kind and expiry and reads its WebAuthn data.
func (s *Service) checkChallenge(ch *Challenge, kind string) (*Challenge, *webauthn.SessionData, error) {
	if ch.Kind != kind || !s.cfg.Now().Before(ch.ExpiresAt) {
		return nil, nil, errChallenge()
	}
	var data webauthn.SessionData
	if err := json.Unmarshal(ch.Data, &data); err != nil {
		return nil, nil, errChallenge()
	}
	// go-webauthn checks its own expiry against the wall clock; ours above uses Config.Now.
	data.Expires = time.Time{}
	return ch, &data, nil
}

// Registration intents, kept with the challenge as its Kind: what begin was for is what finish does.
const (
	kindAddPasskey = "register" // a passkey for an existing, signed-in user
	kindSignUp     = "signup"   // a new user, nobody signed in
)

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
	wu, err := s.loadUser(ctx, user)
	if err != nil {
		return "", nil, err
	}
	// Not on a device that already has a passkey of this user: one device, one passkey.
	exclude := webauthn.Credentials(wu.WebAuthnCredentials()).CredentialDescriptors()
	creation, data, err := s.web.BeginRegistration(wu, webauthn.WithExclusions(exclude))
	if err != nil {
		return "", nil, err
	}
	id, err := s.saveChallenge(ctx, kind, user.ID, data)
	if err != nil {
		return "", nil, err
	}
	opts, err := json.Marshal(creation.Response)
	return id, opts, err
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
	ch, data, err := s.takeChallenge(ctx, challengeID, kindAddPasskey)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, errSessionRequired()
	}
	if ch.UserID != userID {
		return nil, errChallenge()
	}
	return s.finishRegistration(ctx, ch.UserID, data, response, name)
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
	_, data, err := s.checkChallenge(ch, kindSignUp)
	if err != nil {
		return nil, err
	}
	return s.finishRegistration(ctx, ch.UserID, data, response, name)
}

func (s *Service) finishRegistration(ctx context.Context, userID string, data *webauthn.SessionData, response []byte, name string) (*Credential, error) {
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	wu, err := s.loadUser(ctx, user)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, apperr.Wrap(CodeRejected, err)
	}
	cred, err := s.web.CreateCredential(wu, *data, parsed)
	if err != nil {
		return nil, apperr.Wrap(CodeRejected, err)
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	now := s.cfg.Now()
	c := &Credential{
		ID: cred.ID, UserID: userID, PublicKey: cred.PublicKey, SignCount: cred.Authenticator.SignCount,
		Transports: transports, AAGUID: cred.Authenticator.AAGUID,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		Name: strings.TrimSpace(name), CreatedAt: now, LastUsedAt: now,
	}
	if err := s.store.AddCredential(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// BeginLogin starts a sign-in with nobody named: the device answers with who it is.
func (s *Service) BeginLogin(ctx context.Context) (challengeID string, options Options, err error) {
	assertion, data, err := s.web.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	id, err := s.saveChallenge(ctx, "login", "", data)
	if err != nil {
		return "", nil, err
	}
	opts, err := json.Marshal(assertion.Response)
	return id, opts, err
}

// FinishLogin checks the device's signature (response is the JSON from startAuthentication) and
// returns the user and the credential used. Every failure is CodeRejected, whatever the reason.
func (s *Service) FinishLogin(ctx context.Context, challengeID string, response []byte) (*User, *Credential, error) {
	_, data, err := s.takeChallenge(ctx, challengeID, "login")
	if err != nil {
		return nil, nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, nil, errRejected()
	}
	var found *webUser
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, err := s.store.UserByHandle(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		wu, err := s.loadUser(ctx, u)
		if err != nil {
			return nil, err
		}
		found = wu
		return wu, nil
	}
	cred, err := s.web.ValidateDiscoverableLogin(handler, *data, parsed)
	if err != nil || found == nil {
		return nil, nil, errRejected()
	}
	c, err := s.recordUse(ctx, found, cred)
	if err != nil {
		return nil, nil, err
	}
	return found.u, c, nil
}

// BeginConfirm starts a confirmation for the user of a session: the options name only that user's
// passkeys, so the device goes straight to the fingerprint or face prompt.
func (s *Service) BeginConfirm(ctx context.Context, sess *Session) (challengeID string, options Options, err error) {
	if sess == nil {
		return "", nil, errSessionRequired()
	}
	user, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return "", nil, err
	}
	wu, err := s.loadUser(ctx, user)
	if err != nil {
		return "", nil, err
	}
	if len(wu.creds) == 0 {
		return "", nil, errRejected()
	}
	assertion, data, err := s.web.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	id, err := s.saveChallenge(ctx, "confirm", user.ID, data)
	if err != nil {
		return "", nil, err
	}
	opts, err := json.Marshal(assertion.Response)
	return id, opts, err
}

// FinishConfirm checks the confirmation and marks the session confirmed and active now. It also
// ends an idle lock.
func (s *Service) FinishConfirm(ctx context.Context, sess *Session, challengeID string, response []byte) error {
	if sess == nil {
		return errSessionRequired()
	}
	ch, data, err := s.takeChallenge(ctx, challengeID, "confirm")
	if err != nil {
		return err
	}
	if ch.UserID != sess.UserID {
		return errChallenge()
	}
	user, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return errRejected()
	}
	wu, err := s.loadUser(ctx, user)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return errRejected()
	}
	cred, err := s.web.ValidateLogin(wu, *data, parsed)
	if err != nil {
		return errRejected()
	}
	if _, err := s.recordUse(ctx, wu, cred); err != nil {
		return err
	}
	now := s.cfg.Now()
	sess.LastActiveAt, sess.ConfirmedAt = now, now
	return s.store.TouchSession(ctx, sess)
}

// recordUse finds the stored credential behind a verified assertion and writes its new counter.
// A counter that did not go up means the passkey may have been copied: it is refused.
func (s *Service) recordUse(ctx context.Context, wu *webUser, cred *webauthn.Credential) (*Credential, error) {
	i := slices.IndexFunc(wu.creds, func(c Credential) bool { return bytes.Equal(c.ID, cred.ID) })
	if i < 0 || cred.Authenticator.CloneWarning {
		return nil, errRejected()
	}
	c := wu.creds[i]
	c.SignCount = cred.Authenticator.SignCount
	c.BackupState = cred.Flags.BackupState
	c.LastUsedAt = s.cfg.Now()
	if err := s.store.UpdateCredential(ctx, &c); err != nil {
		return nil, err
	}
	return &c, nil
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
