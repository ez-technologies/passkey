package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/memstore"
	"github.com/ez-technologies/passkey/passkeytest"
)

// smallStore is an app's store: only the seven methods of CeremonyStore exist on it.
type smallStore struct {
	passkey.CeremonyStore
	added []*passkey.Credential
}

func (s *smallStore) AddCredential(ctx context.Context, c *passkey.Credential) error {
	s.added = append(s.added, c)
	return s.CeremonyStore.AddCredential(ctx, c)
}

type ceremonyWorld struct {
	cer   *passkey.Ceremonies
	store *smallStore
	auth  *passkeytest.Authenticator
	ctx   context.Context
}

func newCeremonyWorld(t *testing.T, mod func(*passkey.Config)) *ceremonyWorld {
	t.Helper()
	ctx := context.Background()
	full := memstore.New()
	for _, id := range []string{"u1", "u2"} {
		must(t, full.SaveUser(ctx, &passkey.User{ID: id, Handle: []byte("handle-" + id), Name: id, DisplayName: id}))
	}
	store := &smallStore{CeremonyStore: full}
	cfg := passkey.Config{RPID: "app.example.com", RPName: "Example", Origins: []string{origin}}
	if mod != nil {
		mod(&cfg)
	}
	cer, err := passkey.NewCeremonies(cfg, store)
	must(t, err)
	return &ceremonyWorld{cer: cer, store: store, auth: passkeytest.New(origin), ctx: ctx}
}

func (w *ceremonyWorld) register(t *testing.T, userID string, nc passkey.NewCredential) *passkey.Credential {
	t.Helper()
	id, opts, err := w.cer.BeginRegistration(w.ctx, userID)
	must(t, err)
	resp, err := w.auth.Register(opts)
	must(t, err)
	cred, err := w.cer.FinishRegistration(w.ctx, id, userID, resp, nc)
	must(t, err)
	return cred
}

func (w *ceremonyWorld) confirm(t *testing.T, userID string) (*passkey.Credential, error) {
	t.Helper()
	id, opts, err := w.cer.BeginConfirm(w.ctx, userID)
	must(t, err)
	resp, err := w.auth.SignIn(opts)
	must(t, err)
	return w.cer.FinishConfirm(w.ctx, userID, id, resp)
}

func TestCeremoniesNeedAStoreAndAConfig(t *testing.T) {
	cfg := passkey.Config{RPID: "app.example.com", RPName: "Example", Origins: []string{origin}}
	if _, err := passkey.NewCeremonies(cfg, nil); err == nil {
		t.Fatal("no store was accepted")
	}
	if _, err := passkey.NewCeremonies(passkey.Config{}, memstore.New()); err == nil {
		t.Fatal("an empty config was accepted")
	}
}

func TestCeremoniesKeepTheHandleTheStoreGives(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	_, opts, err := w.cer.BeginRegistration(w.ctx, "u1")
	must(t, err)
	var parsed struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	must(t, json.Unmarshal(opts, &parsed))
	if parsed.User.ID != "aGFuZGxlLXUx" { // "handle-u1"
		t.Fatalf("the device got another handle: %q", parsed.User.ID)
	}
}

func TestCeremoniesCreateNobody(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	if _, _, err := w.cer.BeginRegistration(w.ctx, "nobody"); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestExtraReachesTheStoreWithTheNewCredential(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	extra := &struct{ ApprovedBy string }{"u2"}
	cred := w.register(t, "u1", passkey.NewCredential{Name: " Phone ", Extra: extra})
	if len(w.store.added) != 1 || w.store.added[0].Extra != any(extra) {
		t.Fatalf("the store got %+v", w.store.added)
	}
	if cred.Name != "Phone" {
		t.Fatalf("got %+v", cred)
	}
}

func TestRegistrationFinishesOnlyForTheUserItBeganFor(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	id, opts, err := w.cer.BeginRegistration(w.ctx, "u1")
	must(t, err)
	resp, err := w.auth.Register(opts)
	must(t, err)
	_, err = w.cer.FinishRegistration(w.ctx, id, "u2", resp, passkey.NewCredential{})
	wantCode(t, err, passkey.CodeChallengeExpired)
	if len(w.store.added) != 0 {
		t.Fatal("a credential was stored")
	}
}

func TestCeremoniesSignIn(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	cred := w.register(t, "u1", passkey.NewCredential{})
	id, opts, err := w.cer.BeginLogin(w.ctx)
	must(t, err)
	resp, err := w.auth.SignIn(opts)
	must(t, err)
	user, used, err := w.cer.FinishLogin(w.ctx, id, resp)
	must(t, err)
	if user.ID != "u1" || string(used.ID) != string(cred.ID) {
		t.Fatalf("got %+v %+v", user, used)
	}
	_, _, err = w.cer.FinishLogin(w.ctx, id, resp)
	wantCode(t, err, passkey.CodeChallengeExpired)
}

func TestFinishConfirmReturnsTheCredentialUsed(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	cred := w.register(t, "u1", passkey.NewCredential{})
	used, err := w.confirm(t, "u1")
	must(t, err)
	if string(used.ID) != string(cred.ID) || used.SignCount == 0 {
		t.Fatalf("got %+v", used)
	}
}

func TestConfirmFinishesOnlyForTheUserItBeganFor(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	w.register(t, "u1", passkey.NewCredential{})
	id, opts, err := w.cer.BeginConfirm(w.ctx, "u1")
	must(t, err)
	resp, err := w.auth.SignIn(opts)
	must(t, err)
	_, err = w.cer.FinishConfirm(w.ctx, "u2", id, resp)
	wantCode(t, err, passkey.CodeChallengeExpired)
}

func TestConfirmWithNoPasskeyIsRefused(t *testing.T) {
	w := newCeremonyWorld(t, nil)
	_, _, err := w.cer.BeginConfirm(w.ctx, "u1")
	wantCode(t, err, passkey.CodeRejected)
}

func TestACopyAtAConfirmationIsReportedToo(t *testing.T) {
	var got *passkey.Credential
	w := newCeremonyWorld(t, func(c *passkey.Config) {
		c.OnCredentialCopied = func(_ context.Context, cred passkey.Credential) { got = &cred }
	})
	cred := w.register(t, "u1", passkey.NewCredential{})
	for range 2 {
		_, err := w.confirm(t, "u1")
		must(t, err)
	}
	if got != nil {
		t.Fatal("a normal confirmation reported a copy")
	}
	w.auth.Credentials[0].SignCount = 0
	_, err := w.confirm(t, "u1")
	wantCode(t, err, passkey.CodeRejected)
	if got == nil || string(got.ID) != string(cred.ID) {
		t.Fatalf("the copy was not reported: %+v", got)
	}
}
