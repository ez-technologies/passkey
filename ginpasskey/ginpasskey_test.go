package ginpasskey_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/ginpasskey"
	"github.com/ez-technologies/passkey/internal/softauthn"
	"github.com/ez-technologies/passkey/memstore"
)

const origin = "http://localhost:5173"

type app struct {
	t      *testing.T
	svc    *passkey.Service
	srv    *httptest.Server
	client *http.Client
	auth   *softauthn.Authenticator
	now    time.Time
}

func newApp(t *testing.T, mod func(*passkey.Config), h *ginpasskey.Handlers) *app {
	t.Helper()
	gin.SetMode(gin.TestMode)
	a := &app{t: t, auth: softauthn.New(origin), now: time.Now()}
	cfg := passkey.Config{
		RPID: "localhost", RPName: "Test", Origins: []string{origin},
		Cookie: passkey.CookieConfig{Insecure: true}, Now: func() time.Time { return a.now },
	}
	if mod != nil {
		mod(&cfg)
	}
	svc, err := passkey.New(cfg, memstore.New())
	if err != nil {
		t.Fatal(err)
	}
	a.svc = svc
	if h == nil {
		var n atomic.Int64
		h = &ginpasskey.Handlers{NewUser: func(_ *gin.Context, req ginpasskey.SignUp) (passkey.User, error) {
			return passkey.User{ID: fmt.Sprintf("user-%d", n.Add(1)), Name: req.Name, DisplayName: req.DisplayName}, nil
		}}
	}
	h.Service = svc
	r := gin.New()
	h.Mount(r.Group("/auth/passkey"))
	api := r.Group("/api", ginpasskey.RequireSession(svc))
	api.GET("/me", func(c *gin.Context) { c.JSON(200, gin.H{"user": ginpasskey.SessionFrom(c).UserID}) })
	api.POST("/members/approve", ginpasskey.RequireFresh(svc, "member.approve"), func(c *gin.Context) { c.Status(204) })
	r.POST("/fresh-only", ginpasskey.RequireFresh(svc, "member.approve"), func(c *gin.Context) { c.Status(204) })
	a.srv = httptest.NewServer(r)
	t.Cleanup(a.srv.Close)
	a.newBrowser()
	return a
}

func (a *app) newBrowser() {
	jar, _ := cookiejar.New(nil)
	a.client = &http.Client{Jar: jar}
}

func (a *app) call(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (a *app) ceremony(kind string, answer func([]byte) ([]byte, error), begin any, extra map[string]any) (int, map[string]any) {
	a.t.Helper()
	status, out := a.call("POST", "/auth/passkey/"+kind+"/begin", begin)
	if status != 200 {
		return status, out
	}
	opts, _ := json.Marshal(out["options"])
	cred, err := answer(opts)
	if err != nil {
		a.t.Fatal(err)
	}
	body := map[string]any{"challengeId": out["challengeId"], "credential": json.RawMessage(cred)}
	for k, v := range extra {
		body[k] = v
	}
	return a.call("POST", "/auth/passkey/"+kind+"/finish", body)
}

func (a *app) signUp(name string) map[string]any {
	a.t.Helper()
	status, out := a.ceremony("register", a.auth.Register, map[string]any{"name": name, "displayName": name}, map[string]any{"passkeyName": "Laptop"})
	if status != 200 {
		a.t.Fatalf("sign-up: %d %v", status, out)
	}
	return out
}

func want(t *testing.T, status int, out map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || (wantCode != "" && out["code"] != wantCode) {
		t.Fatalf("got %d %v, want %d %s", status, out, wantStatus, wantCode)
	}
}

func TestSignUpSignOutSignIn(t *testing.T) {
	a := newApp(t, nil, nil)
	out := a.signUp("ada")
	if out["user"].(map[string]any)["name"] != "ada" || out["signedIn"] != true {
		t.Fatalf("sign-up answer %v", out)
	}
	status, me := a.call("GET", "/api/me", nil)
	want(t, status, me, 200, "")
	status, sess := a.call("GET", "/auth/passkey/session", nil)
	want(t, status, sess, 200, "")
	if sess["hasPasskey"] != true || sess["user"].(map[string]any)["displayName"] != "ada" {
		t.Fatalf("session %v", sess)
	}

	status, _ = a.call("POST", "/auth/passkey/logout", nil)
	want(t, status, nil, 204, "")
	status, out = a.call("GET", "/api/me", nil)
	want(t, status, out, 401, string(passkey.CodeSessionRequired))

	a.newBrowser() // same device, fresh browser
	status, out = a.ceremony("login", a.auth.SignIn, nil, nil)
	want(t, status, out, 200, "")
	if out["user"].(map[string]any)["id"] != me["user"] {
		t.Fatalf("signed in as %v, signed up as %v", out["user"], me["user"])
	}
	status, _ = a.call("GET", "/api/me", nil)
	want(t, status, nil, 200, "")
}

func TestSignUpClosed(t *testing.T) {
	a := newApp(t, nil, &ginpasskey.Handlers{})
	status, out := a.call("POST", "/auth/passkey/register/begin", map[string]any{"name": "x"})
	want(t, status, out, 401, string(passkey.CodeSessionRequired))
}

func TestBadJSON(t *testing.T) {
	a := newApp(t, nil, nil)
	req, _ := http.NewRequest("POST", a.srv.URL+"/auth/passkey/login/finish", bytes.NewReader([]byte("{nope")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestAddSecondPasskeyNeedsFreshConfirmation(t *testing.T) {
	a := newApp(t, func(c *passkey.Config) { c.SensitiveActions = []string{ginpasskey.ActionAddPasskey} }, nil)
	a.signUp("ada")
	a.now = a.now.Add(10 * time.Minute)
	phone := softauthn.New(origin)
	status, out := a.ceremony("register", phone.Register, nil, nil)
	want(t, status, out, 403, string(passkey.CodeConfirmationRequired))
	if out["action"] != ginpasskey.ActionAddPasskey {
		t.Fatalf("answer %v", out)
	}
	status, out = a.ceremony("confirm", a.auth.SignIn, nil, nil)
	want(t, status, out, 200, "")
	status, out = a.ceremony("register", phone.Register, nil, map[string]any{"passkeyName": "Phone"})
	want(t, status, out, 200, "")

	req, _ := http.NewRequest("GET", a.srv.URL+"/auth/passkey/credentials", nil)
	resp, _ := a.client.Do(req)
	var list []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list) != 2 || list[0]["current"] != true || list[1]["name"] != "Phone" {
		t.Fatalf("credentials %v", list)
	}
	// Both passkeys belong to the same user.
	a.newBrowser()
	status, out = a.ceremony("login", phone.SignIn, nil, nil)
	want(t, status, out, 200, "")
}

func TestSensitiveActionRoute(t *testing.T) {
	a := newApp(t, func(c *passkey.Config) {
		c.SensitiveActions = []string{"member.approve"}
		c.FreshFor = 5 * time.Minute
	}, nil)
	status, out := a.call("POST", "/fresh-only", nil)
	want(t, status, out, 401, string(passkey.CodeSessionRequired))
	a.signUp("ada")
	status, out = a.call("POST", "/api/members/approve", nil)
	want(t, status, out, 204, "")
	a.now = a.now.Add(6 * time.Minute)
	status, out = a.call("POST", "/api/members/approve", nil)
	want(t, status, out, 403, string(passkey.CodeConfirmationRequired))
	status, out = a.call("POST", "/fresh-only", nil)
	want(t, status, out, 403, string(passkey.CodeConfirmationRequired))
	status, out = a.ceremony("confirm", a.auth.SignIn, nil, nil)
	want(t, status, out, 200, "")
	status, out = a.call("POST", "/api/members/approve", nil)
	want(t, status, out, 204, "")
}

func TestIdleLockAndConfirm(t *testing.T) {
	a := newApp(t, func(c *passkey.Config) { c.ReconfirmAfter = 10 * time.Minute }, nil)
	a.signUp("ada")
	a.now = a.now.Add(11 * time.Minute)
	status, out := a.call("GET", "/api/me", nil)
	want(t, status, out, 401, string(passkey.CodeReconfirmRequired))
	status, out = a.call("GET", "/auth/passkey/session", nil)
	want(t, status, out, 401, string(passkey.CodeReconfirmRequired))
	// A locked session cannot add a passkey.
	status, out = a.call("POST", "/auth/passkey/register/begin", nil)
	want(t, status, out, 401, string(passkey.CodeReconfirmRequired))
	status, out = a.ceremony("confirm", a.auth.SignIn, nil, nil)
	want(t, status, out, 200, "")
	status, out = a.call("GET", "/api/me", nil)
	want(t, status, out, 200, "")
}

func TestOneTimeCodeRoute(t *testing.T) {
	a := newApp(t, nil, nil)
	code, _, err := a.svc.CreateCode(t.Context(), passkey.User{ID: "u9", Name: "grace", DisplayName: "Grace"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, out := a.call("POST", "/auth/passkey/code", map[string]any{"code": "WRONG"})
	want(t, status, out, 401, string(passkey.CodeInvalidCode))
	status, out = a.call("POST", "/auth/passkey/code", map[string]any{"code": code})
	want(t, status, out, 200, "")
	status, sess := a.call("GET", "/auth/passkey/session", nil)
	want(t, status, sess, 200, "")
	if sess["hasPasskey"] != false {
		t.Fatalf("session %v", sess)
	}
	// Signed in with the code, the person registers a passkey for the same account.
	status, out = a.ceremony("register", a.auth.Register, nil, nil)
	want(t, status, out, 200, "")
	if out["user"].(map[string]any)["id"] != "u9" {
		t.Fatalf("registered for %v", out["user"])
	}
	status, out = a.call("POST", "/auth/passkey/code", map[string]any{"code": code})
	want(t, status, out, 401, string(passkey.CodeInvalidCode))
}

func TestRemovePasskey(t *testing.T) {
	a := newApp(t, nil, nil)
	a.signUp("ada")
	req, _ := http.NewRequest("GET", a.srv.URL+"/auth/passkey/credentials", nil)
	resp, _ := a.client.Do(req)
	var list []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	status, _ := a.call("DELETE", "/auth/passkey/credentials/"+list[0]["id"].(string), nil)
	want(t, status, nil, 204, "")
	status, _ = a.call("DELETE", "/auth/passkey/credentials/"+list[0]["id"].(string), nil)
	want(t, status, nil, 404, "")
	a.newBrowser()
	status, out := a.ceremony("login", a.auth.SignIn, nil, nil)
	want(t, status, out, 401, string(passkey.CodeRejected))
}

func TestOnRegisteredCanRefuse(t *testing.T) {
	h := &ginpasskey.Handlers{
		NewUser: func(_ *gin.Context, req ginpasskey.SignUp) (passkey.User, error) {
			return passkey.User{ID: "new", Name: req.Name}, nil
		},
		OnRegistered: func(*gin.Context, *passkey.User, *passkey.Credential, bool) error {
			return fmt.Errorf("no room")
		},
	}
	a := newApp(t, nil, h)
	status, out := a.ceremony("register", a.auth.Register, map[string]any{"name": "x"}, nil)
	want(t, status, out, 500, "")
	if out["error"] != "something went wrong" {
		t.Fatalf("an internal error leaked: %v", out)
	}
	status, _ = a.call("GET", "/auth/passkey/session", nil)
	want(t, status, nil, 401, "")
	creds, _ := a.svc.Credentials(t.Context(), "new")
	if len(creds) != 0 {
		t.Fatal("the refused passkey was kept")
	}
}

func TestSignInReplacesThePreviousSession(t *testing.T) {
	a := newApp(t, nil, nil)
	a.signUp("ada")
	before := a.client.Jar.Cookies(mustURL(a.srv.URL))
	status, out := a.ceremony("login", a.auth.SignIn, nil, nil)
	want(t, status, out, 200, "")
	after := a.client.Jar.Cookies(mustURL(a.srv.URL))
	if len(before) != 1 || len(after) != 1 || before[0].Value == after[0].Value {
		t.Fatalf("cookies before %v after %v", before, after)
	}
	// The old token no longer works.
	req, _ := http.NewRequest("GET", a.srv.URL+"/api/me", nil)
	req.AddCookie(before[0])
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("the old session still works: %d", resp.StatusCode)
	}
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
