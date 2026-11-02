package passkey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
)

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// StartSession signs a user in: it stores a new session and sets its cookie on w. credentialID is
// the passkey used, or nil for a session started another way (a one-time code). The session counts
// as confirmed now.
func (s *Service) StartSession(ctx context.Context, w http.ResponseWriter, userID string, credentialID []byte) (*Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	sess := &Session{
		ID: hashOf(token), UserID: userID, CredentialID: credentialID,
		CreatedAt: now, ExpiresAt: now.Add(s.cfg.SessionLifetime), LastActiveAt: now, ConfirmedAt: now,
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	s.setCookie(w, token, int(s.cfg.SessionLifetime.Seconds()))
	return sess, nil
}

func (s *Service) setCookie(w http.ResponseWriter, value string, maxAge int) {
	c := s.cfg.Cookie
	http.SetCookie(w, &http.Cookie{
		Name: c.Name, Value: value, Path: c.Path, Domain: c.Domain, MaxAge: maxAge,
		HttpOnly: true, Secure: !c.Insecure, SameSite: c.SameSite,
	})
}

// Session reads the session of a request.
//
// It returns CodeSessionRequired when there is none or it has ended. When the session has been idle
// longer than Config.ReconfirmAfter it returns the session AND an error with CodeReconfirmRequired:
// the session is locked, and only the confirm ceremony (BeginConfirm, FinishConfirm) and sign-out
// may use it. Otherwise the session is marked active now (written at most once per TouchEvery).
func (s *Service) Session(ctx context.Context, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(s.cfg.Cookie.Name)
	if err != nil || cookie.Value == "" {
		return nil, errSessionRequired()
	}
	sess, err := s.store.GetSession(ctx, hashOf(cookie.Value))
	if errors.Is(err, ErrNotFound) {
		return nil, errSessionRequired()
	}
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	if !now.Before(sess.ExpiresAt) {
		_ = s.store.DeleteSession(ctx, sess.ID)
		return nil, errSessionRequired()
	}
	if s.cfg.ReconfirmAfter > 0 && now.Sub(sess.LastActiveAt) > s.cfg.ReconfirmAfter {
		return sess, errReconfirm()
	}
	if now.Sub(sess.LastActiveAt) >= s.cfg.TouchEvery {
		sess.LastActiveAt = now
		if err := s.store.TouchSession(ctx, sess); err != nil {
			return nil, err
		}
	}
	return sess, nil
}

// SignOut ends the request's session, if any, and clears its cookie.
func (s *Service) SignOut(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	s.setCookie(w, "", -1)
	cookie, err := r.Cookie(s.cfg.Cookie.Name)
	if err != nil || cookie.Value == "" {
		return nil
	}
	return s.store.DeleteSession(ctx, hashOf(cookie.Value))
}

// SignOutEverywhere ends every session of a user, on every device.
func (s *Service) SignOutEverywhere(ctx context.Context, userID string) error {
	return s.store.DeleteUserSessions(ctx, userID)
}

// IsSensitive reports whether action is one of Config.SensitiveActions.
func (s *Service) IsSensitive(action string) bool {
	return slices.Contains(s.cfg.SensitiveActions, action)
}

// CheckFresh says whether sess may do action now. An action that is not in
// Config.SensitiveActions always may. A sensitive one needs the last confirmation to be at most
// Config.FreshFor old; otherwise the answer is CodeConfirmationRequired, carrying the action name.
func (s *Service) CheckFresh(sess *Session, action string) error {
	if sess == nil {
		return errSessionRequired()
	}
	if !s.IsSensitive(action) {
		return nil
	}
	if s.cfg.Now().Sub(sess.ConfirmedAt) > s.cfg.FreshFor {
		return errConfirmation(action)
	}
	return nil
}
