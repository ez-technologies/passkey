package passkey

import (
	"bytes"
	"context"
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

// Options are the WebAuthn options a begin step hands to the browser, as JSON. Pass them to
// startRegistration / startAuthentication of @simplewebauthn/browser as optionsJSON.
type Options = json.RawMessage

// Ceremonies runs only the WebAuthn ceremonies: making a passkey, signing in with one, confirming
// with one. Sessions, cookies, the creating of users and one-time codes are left to the app. It is
// what a Service is built on, and is safe for concurrent use.
//
// Only RPID, RPName, Origins, ChallengeTimeout, OnCredentialCopied and Now of the Config apply.
type Ceremonies struct {
	cfg   Config
	store CeremonyStore
	web   *webauthn.WebAuthn
}

// NewCredential is what the app adds to a passkey being made.
type NewCredential struct {
	// Name is a label for the person ("Laptop", "Phone").
	Name string
	// Extra reaches the store's AddCredential as Credential.Extra.
	Extra any
}

// NewCeremonies builds Ceremonies on a store.
func NewCeremonies(cfg Config, store CeremonyStore) (*Ceremonies, error) {
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
	return &Ceremonies{cfg: c, store: store, web: web}, nil
}

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

func (s *Ceremonies) loadUser(ctx context.Context, u *User) (*webUser, error) {
	creds, err := s.store.Credentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return &webUser{u: u, creds: creds}, nil
}

func (s *Ceremonies) saveChallenge(ctx context.Context, kind, userID string, data *webauthn.SessionData) (string, error) {
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

func (s *Ceremonies) takeChallenge(ctx context.Context, id, kind string) (*Challenge, *webauthn.SessionData, error) {
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
func (s *Ceremonies) checkChallenge(ch *Challenge, kind string) (*Challenge, *webauthn.SessionData, error) {
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

// BeginRegistration starts adding a passkey to an existing user. A user the store does not know is
// ErrNotFound: Ceremonies create nobody. It returns the challenge id to send back with the finish,
// and the options for the browser.
func (s *Ceremonies) BeginRegistration(ctx context.Context, userID string) (challengeID string, options Options, err error) {
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	return s.beginRegistration(ctx, user, kindAddPasskey)
}

func (s *Ceremonies) beginRegistration(ctx context.Context, user *User, kind string) (string, Options, error) {
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

// FinishRegistration finishes a BeginRegistration: it checks what the device made (response is the
// JSON from startRegistration) and stores the new credential.
//
// userID is the user of the session that finishes it, and must be the user the registration began
// for. Pass "" when there is no session: the answer is then CodeSessionRequired, and the challenge
// is used up. A challenge of a sign-up is refused (CodeChallengeExpired).
func (s *Ceremonies) FinishRegistration(ctx context.Context, challengeID, userID string, response []byte, nc NewCredential) (*Credential, error) {
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
	return s.finishRegistration(ctx, ch.UserID, data, response, nc)
}

func (s *Ceremonies) finishRegistration(ctx context.Context, userID string, data *webauthn.SessionData, response []byte, nc NewCredential) (*Credential, error) {
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
		Name: strings.TrimSpace(nc.Name), CreatedAt: now, LastUsedAt: now, Extra: nc.Extra,
	}
	if err := s.store.AddCredential(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// BeginLogin starts a sign-in with nobody named: the device answers with who it is.
func (s *Ceremonies) BeginLogin(ctx context.Context) (challengeID string, options Options, err error) {
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
func (s *Ceremonies) FinishLogin(ctx context.Context, challengeID string, response []byte) (*User, *Credential, error) {
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

// BeginConfirm starts a confirmation that it is this user: the options name only that user's
// passkeys, so the device goes straight to the fingerprint or face prompt. A user with no passkey
// is CodeRejected.
func (s *Ceremonies) BeginConfirm(ctx context.Context, userID string) (challengeID string, options Options, err error) {
	user, err := s.store.UserByID(ctx, userID)
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

// FinishConfirm checks a confirmation, which must be finished for the user it began for, and
// returns the credential used.
func (s *Ceremonies) FinishConfirm(ctx context.Context, userID, challengeID string, response []byte) (*Credential, error) {
	ch, data, err := s.takeChallenge(ctx, challengeID, "confirm")
	if err != nil {
		return nil, err
	}
	if ch.UserID != userID {
		return nil, errChallenge()
	}
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return nil, errRejected()
	}
	wu, err := s.loadUser(ctx, user)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, errRejected()
	}
	cred, err := s.web.ValidateLogin(wu, *data, parsed)
	if err != nil {
		return nil, errRejected()
	}
	return s.recordUse(ctx, wu, cred)
}

// recordUse finds the stored credential behind a verified assertion and writes its new counter.
// A counter that did not go up means the passkey may have been copied: it is refused, and the app
// is told through Config.OnCredentialCopied.
func (s *Ceremonies) recordUse(ctx context.Context, wu *webUser, cred *webauthn.Credential) (*Credential, error) {
	i := slices.IndexFunc(wu.creds, func(c Credential) bool { return bytes.Equal(c.ID, cred.ID) })
	if i < 0 {
		return nil, errRejected()
	}
	if cred.Authenticator.CloneWarning {
		if s.cfg.OnCredentialCopied != nil {
			s.cfg.OnCredentialCopied(ctx, wu.creds[i])
		}
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
