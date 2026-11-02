// Package passkeytest runs passkey ceremonies in Go tests, with no browser and no real device.
//
// An Authenticator is a software passkey device. Hand it the options a begin step returns and it
// answers with the JSON a browser would send to the finish step. The functions SignUp, Register,
// SignIn and Confirm run a whole ceremony against a passkey.Service in one call:
//
//	svc, _ := passkey.New(cfg, memstore.New())
//	device := passkeytest.New("https://example.com") // one of cfg.Origins
//	cred, err := passkeytest.SignUp(ctx, svc, device, passkey.User{ID: "u1", Name: "ada"})
//	user, cred, err := passkeytest.SignIn(ctx, svc, device)
//
// Over HTTP (ginpasskey or your own routes), post to the begin route, pass the "options" of its
// answer to Authenticator.Register or Authenticator.SignIn, and post the result as "credential"
// to the finish route.
package passkeytest

import (
	"context"

	"github.com/ez-technologies/passkey"
)

// SignUp makes the first passkey of a new user u on device: BeginSignUp, then FinishSignUp.
// Start a session for them with svc.StartSession when the test needs one.
func SignUp(ctx context.Context, svc *passkey.Service, device *Authenticator, u passkey.User) (*passkey.Credential, error) {
	id, opts, err := svc.BeginSignUp(ctx, u)
	if err != nil {
		return nil, err
	}
	resp, err := device.Register(opts)
	if err != nil {
		return nil, err
	}
	return svc.FinishSignUp(ctx, id, resp, "")
}

// Register adds a passkey on device to the existing user u, as their signed-in session would:
// BeginRegistration, then FinishRegistration for u.ID.
func Register(ctx context.Context, svc *passkey.Service, device *Authenticator, u passkey.User) (*passkey.Credential, error) {
	id, opts, err := svc.BeginRegistration(ctx, u)
	if err != nil {
		return nil, err
	}
	resp, err := device.Register(opts)
	if err != nil {
		return nil, err
	}
	return svc.FinishRegistration(ctx, id, u.ID, resp, "")
}

// SignIn signs in with a passkey on device: BeginLogin, then FinishLogin. It returns who signed in
// and the passkey used; start a session with svc.StartSession(ctx, w, user.ID, cred.ID).
func SignIn(ctx context.Context, svc *passkey.Service, device *Authenticator) (*passkey.User, *passkey.Credential, error) {
	id, opts, err := svc.BeginLogin(ctx)
	if err != nil {
		return nil, nil, err
	}
	resp, err := device.SignIn(opts)
	if err != nil {
		return nil, nil, err
	}
	return svc.FinishLogin(ctx, id, resp)
}

// Confirm confirms sess with a passkey on device (BeginConfirm, then FinishConfirm): the session
// is fresh for sensitive actions, and unlocked if it was locked for idleness.
func Confirm(ctx context.Context, svc *passkey.Service, device *Authenticator, sess *passkey.Session) error {
	id, opts, err := svc.BeginConfirm(ctx, sess)
	if err != nil {
		return err
	}
	resp, err := device.SignIn(opts)
	if err != nil {
		return err
	}
	return svc.FinishConfirm(ctx, sess, id, resp)
}
