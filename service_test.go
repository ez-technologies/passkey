package passkey_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ez-technologies/apperr"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/internal/softauthn"
	"github.com/ez-technologies/passkey/memstore"
)

const origin = "https://app.example.com"

type harness struct {
	t    *testing.T
	svc  *passkey.Service
	now  time.Time
	auth *softauthn.Authenticator
	ctx  context.Context
}

func newHarness(t *testing.T, mod func(*passkey.Config)) *harness {
	t.Helper()
	h := &harness{t: t, now: time.Now(), auth: softauthn.New(origin), ctx: context.Background()}
	cfg := passkey.Config{RPID: "app.example.com", RPName: "Example", Origins: []string{origin}, Now: func() time.Time { return h.now }}
	if mod != nil {
		mod(&cfg)
	}
	svc, err := passkey.New(cfg, memstore.New())
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h
}

func (h *harness) wait(d time.Duration) { h.now = h.now.Add(d) }

func (h *harness) register(id string) *passkey.Credential {
	h.t.Helper()
	ch, opts, err := h.svc.BeginRegistration(h.ctx, passkey.User{ID: id, Name: id + "@example.com", DisplayName: strings.ToUpper(id)})
	must(h.t, err)
	resp, err := h.auth.Register(opts)
	must(h.t, err)
	cred, err := h.svc.FinishRegistration(h.ctx, ch, id, resp, "Laptop")
	must(h.t, err)
	return cred
}

func (h *harness) signIn() (*passkey.User, *passkey.Credential, error) {
	h.t.Helper()
	ch, opts, err := h.svc.BeginLogin(h.ctx)
	must(h.t, err)
	resp, err := h.auth.SignIn(opts)
	must(h.t, err)
	return h.svc.FinishLogin(h.ctx, ch, resp)
}

// startSession signs in and returns the request a browser would send next, cookie included.
func (h *harness) startSession(userID string, credID []byte) (*http.Request, *http.Cookie) {
	h.t.Helper()
	rec := httptest.NewRecorder()
	_, err := h.svc.StartSession(h.ctx, rec, userID, credID)
	must(h.t, err)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		h.t.Fatalf("StartSession set %d cookies", len(cookies))
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookies[0])
	return r, cookies[0]
}

func (h *harness) confirm(sess *passkey.Session) error {
	h.t.Helper()
	ch, opts, err := h.svc.BeginConfirm(h.ctx, sess)
	if err != nil {
		return err
	}
	resp, err := h.auth.SignIn(opts)
	must(h.t, err)
	return h.svc.FinishConfirm(h.ctx, sess, ch, resp)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantCode(t *testing.T, err error, code apperr.Code) {
	t.Helper()
	if got := apperr.CodeOf(err); got != code {
		t.Fatalf("got error %v (code %q), want code %q", err, got, code)
	}
}

func TestRegisterThenSignIn(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.register("u1")
	if cred.Name != "Laptop" || cred.UserID != "u1" || len(cred.Transports) != 1 {
		t.Fatalf("credential: %+v", cred)
	}
	user, used, err := h.signIn()
	must(t, err)
	if user.ID != "u1" || user.DisplayName != "U1" || string(used.ID) != string(cred.ID) || used.SignCount != 1 {
		t.Fatalf("signed in as %+v with %+v", user, used)
	}
	r, _ := h.startSession(user.ID, used.ID)
	sess, err := h.svc.Session(h.ctx, r)
	must(t, err)
	if sess.UserID != "u1" {
		t.Fatalf("session of %q", sess.UserID)
	}
}

func TestSecondRegistrationKeepsHandleAndUpdatesName(t *testing.T) {
	h := newHarness(t, nil)
	h.register("u1")
	before, _ := h.svc.Store().UserByID(h.ctx, "u1")
	h.auth = softauthn.New(origin) // another device
	ch, opts, err := h.svc.BeginRegistration(h.ctx, passkey.User{ID: "u1", DisplayName: "New name"})
	must(t, err)
	resp, err := h.auth.Register(opts)
	must(t, err)
	_, err = h.svc.FinishRegistration(h.ctx, ch, "u1", resp, "Phone")
	must(t, err)
	after, _ := h.svc.Store().UserByID(h.ctx, "u1")
	if string(after.Handle) != string(before.Handle) || after.DisplayName != "New name" || after.Name != before.Name {
		t.Fatalf("user changed from %+v to %+v", before, after)
	}
	creds, _ := h.svc.Credentials(h.ctx, "u1")
	if len(creds) != 2 {
		t.Fatalf("%d credentials, want 2", len(creds))
	}
}

func TestSameDeviceCannotRegisterTwice(t *testing.T) {
	h := newHarness(t, nil)
	h.register("u1")
	_, opts, err := h.svc.BeginRegistration(h.ctx, passkey.User{ID: "u1"})
	must(t, err)
	if _, err := h.auth.Register(opts); err == nil {
		t.Fatal("the options did not exclude the passkey this device already has")
	}
}

func TestRegistrationNeedsUserID(t *testing.T) {
	h := newHarness(t, nil)
	_, _, err := h.svc.BeginRegistration(h.ctx, passkey.User{})
	wantCode(t, err, passkey.CodeBadRequest)
	if passkey.HTTPStatus(err) != http.StatusBadRequest {
		t.Fatalf("status %d", passkey.HTTPStatus(err))
	}
}

func TestFinishRegistrationForAnotherUser(t *testing.T) {
	h := newHarness(t, nil)
	ch, opts, err := h.svc.BeginRegistration(h.ctx, passkey.User{ID: "u1"})
	must(t, err)
	resp, _ := h.auth.Register(opts)
	_, err = h.svc.FinishRegistration(h.ctx, ch, "u2", resp, "")
	wantCode(t, err, passkey.CodeChallengeExpired)
}

func TestChallengeWorksOnce(t *testing.T) {
	h := newHarness(t, nil)
	h.register("u1")
	ch, opts, err := h.svc.BeginLogin(h.ctx)
	must(t, err)
	resp, _ := h.auth.SignIn(opts)
	_, _, err = h.svc.FinishLogin(h.ctx, ch, resp)
	must(t, err)
	_, _, err = h.svc.FinishLogin(h.ctx, ch, resp)
	wantCode(t, err, passkey.CodeChallengeExpired)
}

func TestChallengeExpires(t *testing.T) {
	h := newHarness(t, func(c *passkey.Config) { c.ChallengeTimeout = time.Minute })
	h.register("u1")
	ch, opts, err := h.svc.BeginLogin(h.ctx)
	must(t, err)
	resp, _ := h.auth.SignIn(opts)
	h.wait(61 * time.Second)
	_, _, err = h.svc.FinishLogin(h.ctx, ch, resp)
	wantCode(t, err, passkey.CodeChallengeExpired)
}

func TestUnknownPasskeyIsRejected(t *testing.T) {
	other := newHarness(t, nil)
	other.register("u1")
	h := newHarness(t, nil)
	h.auth = other.auth // a passkey this server never saw
	_, _, err := h.signIn()
	wantCode(t, err, passkey.CodeRejected)
}

func TestRemovedPasskeyIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.register("u1")
	must(t, h.svc.RemoveCredential(h.ctx, "u1", cred.ID))
	_, _, err := h.signIn()
	wantCode(t, err, passkey.CodeRejected)
}

func TestCopiedPasskeyIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	h.register("u1")
	_, _, err := h.signIn()
	must(t, err)
	_, _, err = h.signIn()
	must(t, err)
	h.auth.Credentials[0].SignCount = 0 // a copy that signs with an older counter
	_, _, err = h.signIn()
	wantCode(t, err, passkey.CodeRejected)
}

func TestTamperedResponseIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	h.register("u1")
	ch, _, err := h.svc.BeginLogin(h.ctx)
	must(t, err)
	_, _, err = h.svc.FinishLogin(h.ctx, ch, []byte(`{"id":"nope"}`))
	wantCode(t, err, passkey.CodeRejected)
}

func TestNoCookieMeansSessionRequired(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.svc.Session(h.ctx, httptest.NewRequest(http.MethodGet, "/", nil))
	wantCode(t, err, passkey.CodeSessionRequired)
	if passkey.HTTPStatus(err) != http.StatusUnauthorized {
		t.Fatalf("status %d", passkey.HTTPStatus(err))
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "passkey_session", Value: "made-up"})
	_, err = h.svc.Session(h.ctx, r)
	wantCode(t, err, passkey.CodeSessionRequired)
}

func TestCookieAttributes(t *testing.T) {
	h := newHarness(t, func(c *passkey.Config) {
		c.Cookie = passkey.CookieConfig{Name: "sid", Path: "/app", Domain: "example.com", SameSite: http.SameSiteStrictMode}
		c.SessionLifetime = 2 * time.Hour
	})
	_, c := h.startSession("u1", nil)
	if c.Name != "sid" || c.Path != "/app" || c.Domain != "example.com" || !c.HttpOnly || !c.Secure ||
		c.SameSite != http.SameSiteStrictMode || c.MaxAge != 7200 || len(c.Value) < 40 {
		t.Fatalf("cookie: %+v", c)
	}
	h2 := newHarness(t, func(c *passkey.Config) { c.Cookie.Insecure = true })
	_, c = h2.startSession("u1", nil)
	if c.Name != "passkey_session" || c.Path != "/" || c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 30*24*3600 {
		t.Fatalf("default cookie: %+v", c)
	}
}

func TestSessionStoresOnlyTheTokenHash(t *testing.T) {
	h := newHarness(t, nil)
	rec := httptest.NewRecorder()
	sess, err := h.svc.StartSession(h.ctx, rec, "u1", nil)
	must(t, err)
	token := rec.Result().Cookies()[0].Value
	if sess.ID == token || strings.Contains(sess.ID, token) || len(sess.ID) != 64 {
		t.Fatalf("session id %q for token %q", sess.ID, token)
	}
}

func TestSessionLifetime(t *testing.T) {
	h := newHarness(t, func(c *passkey.Config) { c.SessionLifetime = time.Hour })
	r, _ := h.startSession("u1", nil)
	h.wait(59 * time.Minute)
	_, err := h.svc.Session(h.ctx, r)
	must(t, err)
	h.wait(time.Minute)
	_, err = h.svc.Session(h.ctx, r)
	wantCode(t, err, passkey.CodeSessionRequired)
}

func TestSignOut(t *testing.T) {
	h := newHarness(t, nil)
	r, _ := h.startSession("u1", nil)
	rec := httptest.NewRecorder()
	must(t, h.svc.SignOut(h.ctx, rec, r))
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Fatalf("sign-out did not clear the cookie: %+v", c)
	}
	_, err := h.svc.Session(h.ctx, r)
	wantCode(t, err, passkey.CodeSessionRequired)
	// Signing out without a session is fine.
	must(t, h.svc.SignOut(h.ctx, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)))
}

func TestSignOutEverywhere(t *testing.T) {
	h := newHarness(t, nil)
	r1, _ := h.startSession("u1", nil)
	r2, _ := h.startSession("u1", nil)
	must(t, h.svc.SignOutEverywhere(h.ctx, "u1"))
	for _, r := range []*http.Request{r1, r2} {
		_, err := h.svc.Session(h.ctx, r)
		wantCode(t, err, passkey.CodeSessionRequired)
	}
}

func TestIdleSessionNeedsReconfirm(t *testing.T) {
	h := newHarness(t, func(c *passkey.Config) { c.ReconfirmAfter = 10 * time.Minute })
	cred := h.register("u1")
	r, _ := h.startSession("u1", cred.ID)
	// Active every 8 minutes: never locked.
	for range 3 {
		h.wait(8 * time.Minute)
		_, err := h.svc.Session(h.ctx, r)
		must(t, err)
	}
	h.wait(11 * time.Minute)
	sess, err := h.svc.Session(h.ctx, r)
	wantCode(t, err, passkey.CodeReconfirmRequired)
	if sess == nil || !passkey.IsReconfirmRequired(err) || passkey.HTTPStatus(err) != http.StatusUnauthorized {
		t.Fatal("a locked session is returned with the error, answered 401")
	}
	must(t, h.confirm(sess))
	_, err = h.svc.Session(h.ctx, r)
	must(t, err)
}

func TestReconfirmZeroMeansNever(t *testing.T) {
	h := newHarness(t, nil)
	r, _ := h.startSession("u1", nil)
	h.wait(29 * 24 * time.Hour)
	_, err := h.svc.Session(h.ctx, r)
	must(t, err)
}

func TestSensitiveActions(t *testing.T) {
	h := newHarness(t, func(c *passkey.Config) {
		c.SensitiveActions = []string{"device.add", "member.approve"}
		c.FreshFor = 5 * time.Minute
	})
	cred := h.register("u1")
	r, _ := h.startSession("u1", cred.ID)
	sess, err := h.svc.Session(h.ctx, r)
	must(t, err)
	must(t, h.svc.CheckFresh(sess, "device.add")) // just signed in
	h.wait(6 * time.Minute)
	sess, _ = h.svc.Session(h.ctx, r)
	err = h.svc.CheckFresh(sess, "member.approve")
	wantCode(t, err, passkey.CodeConfirmationRequired)
	if apperr.ExtraOf(err)["action"] != "member.approve" || passkey.HTTPStatus(err) != http.StatusForbidden {
		t.Fatalf("extra %v, status %d", apperr.ExtraOf(err), passkey.HTTPStatus(err))
	}
	must(t, h.svc.CheckFresh(sess, "profile.edit")) // not sensitive
	must(t, h.confirm(sess))
	sess, _ = h.svc.Session(h.ctx, r)
	must(t, h.svc.CheckFresh(sess, "member.approve"))
	if !h.svc.IsSensitive("device.add") || h.svc.IsSensitive("profile.edit") {
		t.Fatal("IsSensitive")
	}
	wantCode(t, h.svc.CheckFresh(nil, "x"), passkey.CodeSessionRequired)
}

func TestConfirmNeedsThePersonsOwnPasskey(t *testing.T) {
	h := newHarness(t, nil)
	h.register("u1")
	h.auth = softauthn.New(origin)
	h.register("u2")
	r, _ := h.startSession("u1", nil)
	sess, _ := h.svc.Session(h.ctx, r)
	// The options name only u1's passkeys, which this device does not have.
	ch, opts, err := h.svc.BeginConfirm(h.ctx, sess)
	must(t, err)
	if _, err := h.auth.SignIn(opts); err == nil {
		t.Fatal("u2's device answered a confirmation for u1")
	}
	// A u2 sign-in response does not confirm u1's session either.
	_, lopts, _ := h.svc.BeginLogin(h.ctx)
	resp, _ := h.auth.SignIn(lopts)
	wantCode(t, h.svc.FinishConfirm(h.ctx, sess, ch, resp), passkey.CodeRejected)
}

func TestConfirmWithoutPasskey(t *testing.T) {
	h := newHarness(t, nil)
	u := passkey.User{ID: "u1"}
	code, _, err := h.svc.CreateCode(h.ctx, u, time.Hour)
	must(t, err)
	_, err = h.svc.RedeemCode(h.ctx, code)
	must(t, err)
	r, _ := h.startSession("u1", nil)
	sess, _ := h.svc.Session(h.ctx, r)
	_, _, err = h.svc.BeginConfirm(h.ctx, sess)
	wantCode(t, err, passkey.CodeRejected)
}

func TestOneTimeCodes(t *testing.T) {
	h := newHarness(t, func(c *passkey.Config) { c.CodeLength = 12 })
	code, exp, err := h.svc.CreateCode(h.ctx, passkey.User{ID: "u1", Name: "u1", DisplayName: "U1"}, time.Hour)
	must(t, err)
	if len(passkey.NormalizeCode(code)) != 12 || code[5] != '-' || !exp.Equal(h.now.Add(time.Hour)) {
		t.Fatalf("code %q expiring %v", code, exp)
	}
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	u, err := h.svc.RedeemCode(h.ctx, typed)
	must(t, err)
	if u.ID != "u1" {
		t.Fatalf("redeemed for %q", u.ID)
	}
	_, err = h.svc.RedeemCode(h.ctx, code)
	wantCode(t, err, passkey.CodeInvalidCode)
	_, err = h.svc.RedeemCode(h.ctx, "WRONG-CODE0")
	wantCode(t, err, passkey.CodeInvalidCode)

	code2, _, err := h.svc.CreateCode(h.ctx, passkey.User{ID: "u1"}, time.Minute)
	must(t, err)
	h.wait(time.Minute)
	_, err = h.svc.RedeemCode(h.ctx, code2)
	wantCode(t, err, passkey.CodeInvalidCode)

	_, _, err = h.svc.CreateCode(h.ctx, passkey.User{ID: "u1"}, 0)
	if err == nil {
		t.Fatal("a code with no lifetime was made")
	}
}

func TestCodeThenPasskey(t *testing.T) {
	// A person with no passkey gets a code, signs in with it, then registers a passkey.
	h := newHarness(t, nil)
	code, _, err := h.svc.CreateCode(h.ctx, passkey.User{ID: "u1", Name: "u1"}, time.Hour)
	must(t, err)
	u, err := h.svc.RedeemCode(h.ctx, code)
	must(t, err)
	h.startSession(u.ID, nil)
	h.register(u.ID)
	got, _, err := h.signIn()
	must(t, err)
	if got.ID != "u1" {
		t.Fatalf("signed in as %q", got.ID)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := passkey.New(passkey.Config{}, memstore.New()); err == nil {
		t.Fatal("an empty config was accepted")
	}
	if _, err := passkey.New(passkey.Config{RPID: "a.com", RPName: "A", Origins: []string{"https://a.com"}}, nil); err == nil {
		t.Fatal("a nil store was accepted")
	}
	svc, err := passkey.New(passkey.Config{RPID: "a.com", RPName: "A", Origins: []string{"https://a.com"}, ReconfirmAfter: 30 * time.Second}, memstore.New())
	must(t, err)
	c := svc.Config()
	if c.FreshFor != 5*time.Minute || c.ChallengeTimeout != 5*time.Minute || c.TouchEvery != 15*time.Second || c.CodeLength != 10 {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestHTTPStatus(t *testing.T) {
	cases := map[int]error{
		http.StatusInternalServerError: errors.New("boom"),
		http.StatusBadRequest:          apperr.New(passkey.CodeChallengeExpired, "x"),
		http.StatusUnauthorized:        apperr.New(passkey.CodeInvalidCode, "x"),
		http.StatusForbidden:           apperr.ErrForbidden,
	}
	for want, err := range cases {
		if got := passkey.HTTPStatus(err); got != want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", err, got, want)
		}
	}
}
