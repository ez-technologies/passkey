// Package ginpasskey puts a passkey.Service on Gin: the JSON routes the TypeScript client calls,
// and the middleware that guards your own routes.
//
//	h := &ginpasskey.Handlers{Service: svc, NewUser: signUp}
//	h.Mount(r.Group("/auth/passkey"))
//	api := r.Group("/api", ginpasskey.RequireSession(svc))
//	api.POST("/members/:id/approve", ginpasskey.RequireFresh(svc, "member.approve"), approve)
package ginpasskey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ez-technologies/apperr"
	"github.com/gin-gonic/gin"

	"github.com/ez-technologies/passkey"
)

const sessionKey = "passkey.session"

// ActionAddPasskey is the action checked with CheckFresh when a signed-in user adds a passkey, and
// ActionRemovePasskey when they remove one. List them in the SensitiveActions of the policy to make them
// need a fresh confirmation.
const (
	ActionAddPasskey    = "passkey.add"
	ActionRemovePasskey = "passkey.remove"
)

// WriteError answers err as JSON: {"error": text, "code": code, ...extra}, with the status of
// passkey.HTTPStatus. An error without a code is answered 500 with a plain text, and added to
// c.Errors for your logger.
func WriteError(c *gin.Context, err error) {
	status := passkey.HTTPStatus(err)
	body := gin.H{}
	for k, v := range apperr.ExtraOf(err) {
		body[k] = v
	}
	body["error"] = err.Error()
	if code := apperr.CodeOf(err); code != "" {
		body["code"] = code
	}
	if status == http.StatusInternalServerError {
		_ = c.Error(err)
		body = gin.H{"error": "something went wrong"}
	}
	c.AbortWithStatusJSON(status, body)
}

// RequireSession lets a request through only with a live session that is not locked, and keeps
// the session for SessionFrom. Otherwise it answers 401 with passkey.session_required or
// passkey.reconfirm_required.
func RequireSession(svc *passkey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		sess, err := svc.Session(c.Request.Context(), c.Request)
		if err != nil {
			WriteError(c, err)
			return
		}
		c.Set(sessionKey, sess)
		c.Next()
	}
}

// RequireFresh lets a request through only when action may be done now (see
// passkey.Service.CheckFresh): an action not in the policy's SensitiveActions always may, a sensitive one
// needs a recent confirmation, and is otherwise answered 403 with passkey.confirmation_required and
// "action". It reads the session itself when RequireSession did not run before it.
func RequireFresh(svc *passkey.Service, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		sess := SessionFrom(c)
		if sess == nil {
			var err error
			if sess, err = svc.Session(c.Request.Context(), c.Request); err != nil {
				WriteError(c, err)
				return
			}
			c.Set(sessionKey, sess)
		}
		if err := svc.CheckFresh(sess, action); err != nil {
			WriteError(c, err)
			return
		}
		c.Next()
	}
}

// SessionFrom is the session RequireSession (or RequireFresh) found, or nil.
func SessionFrom(c *gin.Context) *passkey.Session {
	v, ok := c.Get(sessionKey)
	if !ok {
		return nil
	}
	sess, _ := v.(*passkey.Session)
	return sess
}

// SignUp is what the browser sends to begin a registration while nobody is signed in.
type SignUp struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// Handlers are the routes of the client. Mount puts them on a router group.
type Handlers struct {
	Service *passkey.Service
	// NewUser decides who a registration is for when nobody is signed in: it gives the new user an
	// id of your app (and may refuse with an error, for a closed sign-up or a taken name). Leave it
	// nil to allow registration only for signed-in users. It must return a NEW user: an existing
	// user's id would let whoever calls it add a passkey to that account. Your own user record can wait for
	// OnRegistered, so a sign-up that is never finished leaves nothing behind.
	NewUser func(c *gin.Context, req SignUp) (passkey.User, error)
	// OnRegistered runs after a passkey is stored; created is true for a sign-up. An error here is
	// answered, and for a sign-up no session starts.
	OnRegistered func(c *gin.Context, user *passkey.User, cred *passkey.Credential, created bool) error
	// OnSignIn runs after a successful sign-in (passkey or code), before the answer.
	OnSignIn func(c *gin.Context, user *passkey.User)
}

// Mount adds the routes to g:
//
//	POST   register/begin    {name?, displayName?}                 -> {challengeId, options}
//	POST   register/finish   {challengeId, credential, passkeyName?} -> {user, signedIn}
//	POST   login/begin                                              -> {challengeId, options}
//	POST   login/finish      {challengeId, credential}             -> {user}
//	POST   confirm/begin                                            -> {challengeId, options}
//	POST   confirm/finish    {challengeId, credential}             -> {confirmedAt}
//	POST   code              {code}                                -> {user}
//	GET    session                                                  -> {user, confirmedAt, expiresAt, hasPasskey}
//	GET    credentials                                              -> [{id, name, createdAt, lastUsedAt}]
//	DELETE credentials/:id                                          -> 204
//	POST   logout                                                   -> 204
//
// Put a rate limit in front of "code" (and ideally the rest) in production.
func (h *Handlers) Mount(g gin.IRouter) {
	g.POST("/register/begin", h.registerBegin)
	g.POST("/register/finish", h.registerFinish)
	g.POST("/login/begin", h.loginBegin)
	g.POST("/login/finish", h.loginFinish)
	g.POST("/confirm/begin", h.confirmBegin)
	g.POST("/confirm/finish", h.confirmFinish)
	g.POST("/code", h.redeemCode)
	g.GET("/session", h.session)
	g.GET("/credentials", RequireSession(h.Service), h.credentials)
	g.DELETE("/credentials/:id", RequireFresh(h.Service, ActionRemovePasskey), h.removeCredential)
	g.POST("/logout", h.logout)
}

type finishRequest struct {
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
	PasskeyName string          `json:"passkeyName"`
}

func bind(c *gin.Context, v any) bool {
	if c.Request.ContentLength == 0 {
		return true
	}
	if err := c.ShouldBindJSON(v); err != nil {
		WriteError(c, apperr.Wrap(passkey.CodeBadRequest, err))
		return false
	}
	return true
}

func userJSON(u *passkey.User) gin.H {
	return gin.H{"id": u.ID, "name": u.Name, "displayName": u.DisplayName}
}

func (h *Handlers) registerBegin(c *gin.Context) {
	ctx := c.Request.Context()
	var req SignUp
	if !bind(c, &req) {
		return
	}
	var user passkey.User
	begin := h.Service.BeginRegistration // a passkey for the signed-in user
	sess, err := h.Service.Session(ctx, c.Request)
	switch {
	case err == nil:
		if err := h.Service.CheckFresh(sess, ActionAddPasskey); err != nil {
			WriteError(c, err)
			return
		}
		user = passkey.User{ID: sess.UserID}
		if stored, err := h.Service.Store().UserByID(ctx, sess.UserID); err == nil {
			user = *stored
		}
	case passkey.IsReconfirmRequired(err):
		WriteError(c, err)
		return
	case h.NewUser == nil:
		WriteError(c, err)
		return
	default:
		if user, err = h.NewUser(c, req); err != nil {
			WriteError(c, err)
			return
		}
		begin = h.Service.BeginSignUp
	}
	// The challenge keeps what this begin was for; finish holds to it.
	id, opts, err := begin(ctx, user)
	if err != nil {
		WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"challengeId": id, "options": opts})
}

func (h *Handlers) registerFinish(c *gin.Context) {
	ctx := c.Request.Context()
	var req finishRequest
	if !bind(c, &req) {
		return
	}
	// What begin was for is kept with the challenge, and finish holds to it: a passkey begun for a
	// signed-in user needs that user's live session here, and never becomes a sign-up.
	var cred *passkey.Credential
	created := false
	sess, err := h.Service.Session(ctx, c.Request)
	switch {
	case err == nil:
		cred, err = h.Service.FinishRegistration(ctx, req.ChallengeID, sess.UserID, req.Credential, req.PasskeyName)
	case passkey.IsReconfirmRequired(err):
		// Locked since begin. The challenge is left as it is: confirm, then send this finish again.
	default:
		// Nobody signed in: a sign-up, or CodeSessionRequired when begin was for a signed-in user.
		cred, err = h.Service.FinishSignUp(ctx, req.ChallengeID, req.Credential, req.PasskeyName)
		created = true
	}
	if err != nil {
		WriteError(c, err)
		return
	}
	user, err := h.Service.Store().UserByID(ctx, cred.UserID)
	if err != nil {
		WriteError(c, err)
		return
	}
	if h.OnRegistered != nil {
		if err := h.OnRegistered(c, user, cred, created); err != nil {
			_ = h.Service.RemoveCredential(ctx, user.ID, cred.ID)
			WriteError(c, err)
			return
		}
	}
	if created {
		if _, err := h.Service.StartSession(ctx, c.Writer, user.ID, cred.ID); err != nil {
			WriteError(c, err)
			return
		}
		if h.OnSignIn != nil {
			h.OnSignIn(c, user)
		}
	}
	c.JSON(http.StatusOK, gin.H{"user": userJSON(user), "signedIn": true})
}

func (h *Handlers) loginBegin(c *gin.Context) {
	id, opts, err := h.Service.BeginLogin(c.Request.Context())
	if err != nil {
		WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"challengeId": id, "options": opts})
}

func (h *Handlers) loginFinish(c *gin.Context) {
	ctx := c.Request.Context()
	var req finishRequest
	if !bind(c, &req) {
		return
	}
	user, cred, err := h.Service.FinishLogin(ctx, req.ChallengeID, req.Credential)
	if err != nil {
		WriteError(c, err)
		return
	}
	// A previous session of this browser ends: one browser, one session.
	_ = h.Service.SignOut(ctx, discard{}, c.Request)
	if _, err := h.Service.StartSession(ctx, c.Writer, user.ID, cred.ID); err != nil {
		WriteError(c, err)
		return
	}
	if h.OnSignIn != nil {
		h.OnSignIn(c, user)
	}
	c.JSON(http.StatusOK, gin.H{"user": userJSON(user)})
}

// lockedOrLive is the request's session, also when it is locked for idleness.
func (h *Handlers) lockedOrLive(c *gin.Context) (*passkey.Session, bool) {
	sess, err := h.Service.Session(c.Request.Context(), c.Request)
	if err != nil && !passkey.IsReconfirmRequired(err) {
		WriteError(c, err)
		return nil, false
	}
	return sess, true
}

func (h *Handlers) confirmBegin(c *gin.Context) {
	sess, ok := h.lockedOrLive(c)
	if !ok {
		return
	}
	id, opts, err := h.Service.BeginConfirm(c.Request.Context(), sess)
	if err != nil {
		WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"challengeId": id, "options": opts})
}

func (h *Handlers) confirmFinish(c *gin.Context) {
	var req finishRequest
	if !bind(c, &req) {
		return
	}
	sess, ok := h.lockedOrLive(c)
	if !ok {
		return
	}
	if err := h.Service.FinishConfirm(c.Request.Context(), sess, req.ChallengeID, req.Credential); err != nil {
		WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"confirmedAt": sess.ConfirmedAt})
}

func (h *Handlers) redeemCode(c *gin.Context) {
	ctx := c.Request.Context()
	var req struct {
		Code string `json:"code"`
	}
	if !bind(c, &req) {
		return
	}
	user, err := h.Service.RedeemCode(ctx, req.Code)
	if err != nil {
		WriteError(c, err)
		return
	}
	_ = h.Service.SignOut(ctx, discard{}, c.Request)
	if _, err := h.Service.StartSession(ctx, c.Writer, user.ID, nil); err != nil {
		WriteError(c, err)
		return
	}
	if h.OnSignIn != nil {
		h.OnSignIn(c, user)
	}
	c.JSON(http.StatusOK, gin.H{"user": userJSON(user)})
}

func (h *Handlers) session(c *gin.Context) {
	ctx := c.Request.Context()
	sess, err := h.Service.Session(ctx, c.Request)
	if err != nil {
		WriteError(c, err)
		return
	}
	user := &passkey.User{ID: sess.UserID}
	if stored, err := h.Service.Store().UserByID(ctx, sess.UserID); err == nil {
		user = stored
	}
	creds, err := h.Service.Credentials(ctx, sess.UserID)
	if err != nil {
		WriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user": userJSON(user), "confirmedAt": sess.ConfirmedAt, "expiresAt": sess.ExpiresAt, "hasPasskey": len(creds) > 0,
	})
}

func (h *Handlers) credentials(c *gin.Context) {
	sess := SessionFrom(c)
	creds, err := h.Service.Credentials(c.Request.Context(), sess.UserID)
	if err != nil {
		WriteError(c, err)
		return
	}
	type item struct {
		ID         string    `json:"id"`
		Name       string    `json:"name"`
		CreatedAt  time.Time `json:"createdAt"`
		LastUsedAt time.Time `json:"lastUsedAt"`
		Current    bool      `json:"current"`
	}
	out := make([]item, 0, len(creds))
	for _, cr := range creds {
		id := base64.RawURLEncoding.EncodeToString(cr.ID)
		out = append(out, item{ID: id, Name: cr.Name, CreatedAt: cr.CreatedAt, LastUsedAt: cr.LastUsedAt,
			Current: id == base64.RawURLEncoding.EncodeToString(sess.CredentialID)})
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) removeCredential(c *gin.Context) {
	sess := SessionFrom(c)
	id, err := base64.RawURLEncoding.DecodeString(c.Param("id"))
	if err != nil {
		WriteError(c, apperr.Wrap(passkey.CodeBadRequest, err))
		return
	}
	err = h.Service.RemoveCredential(c.Request.Context(), sess.UserID, id)
	if errors.Is(err, passkey.ErrNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "no such passkey"})
		return
	}
	if err != nil {
		WriteError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) logout(c *gin.Context) {
	if err := h.Service.SignOut(c.Request.Context(), c.Writer, c.Request); err != nil {
		WriteError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// discard is a ResponseWriter that drops what is written: ending an old session before a new one
// must not write a second cookie of the same name into the answer.
type discard struct{}

func (discard) Header() http.Header         { return http.Header{} }
func (discard) Write(b []byte) (int, error) { return len(b), nil }
func (discard) WriteHeader(int)             {}
