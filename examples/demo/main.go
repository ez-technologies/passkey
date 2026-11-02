// Command demo is a small app that signs people in with passkeys: sign up, sign in, a sensitive
// action that asks for a fresh confirmation, an idle lock, one-time codes and sign out.
//
// Run it from the repository root, after building the client:
//
//	(cd client && npm ci && npm run build)
//	go run ./examples/demo
//
// and open http://localhost:8080. Data is kept in memory: a restart forgets everyone.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ez-technologies/apperr"
	"github.com/gin-gonic/gin"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/ginpasskey"
	"github.com/ez-technologies/passkey/memstore"
)

//go:embed web
var web embed.FS

func main() {
	addr := flag.String("addr", "localhost:8080", "address to listen on")
	origin := flag.String("origin", "http://localhost:8080", "origin the browser uses")
	rpID := flag.String("rp-id", "localhost", "relying-party id (the domain)")
	idle := flag.Duration("idle", 2*time.Minute, "lock after this long idle (0 = never)")
	fresh := flag.Duration("fresh", time.Minute, "how long a confirmation counts for sensitive actions")
	clientDir := flag.String("client", "client", "folder of the built TypeScript client (client/dist inside it)")
	flag.Parse()

	svc, err := passkey.New(passkey.Config{
		RPID: *rpID, RPName: "Passkey demo", Origins: []string{*origin},
		ReconfirmAfter:   *idle,
		SensitiveActions: []string{"code.create", ginpasskey.ActionAddPasskey, ginpasskey.ActionRemovePasskey},
		FreshFor:         *fresh,
	}, memstore.New())
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	h := &ginpasskey.Handlers{Service: svc, NewUser: signUp}
	h.Mount(r.Group("/auth/passkey"))

	api := r.Group("/api", ginpasskey.RequireSession(svc))
	// A sensitive action: a code that signs this account in on another device, once, for 15 minutes.
	api.POST("/codes", ginpasskey.RequireFresh(svc, "code.create"), func(c *gin.Context) {
		sess := ginpasskey.SessionFrom(c)
		user, err := svc.Store().UserByID(c.Request.Context(), sess.UserID)
		if err != nil {
			ginpasskey.WriteError(c, err)
			return
		}
		code, expires, err := svc.CreateCode(c.Request.Context(), *user, 15*time.Minute)
		if err != nil {
			ginpasskey.WriteError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"code": code, "expiresAt": expires})
	})
	r.GET("/api/settings", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"idle": idle.String(), "fresh": fresh.String()})
	})

	page, _ := fs.Sub(web, "web")
	r.StaticFS("/client", http.Dir(*clientDir+"/dist"))
	r.StaticFS("/vendor/simplewebauthn", http.Dir(*clientDir+"/node_modules/@simplewebauthn/browser/esm"))
	r.NoRoute(gin.WrapH(http.FileServer(http.FS(page))))

	log.Printf("passkey demo on %s (lock after %s idle, confirmations fresh for %s)", *origin, *idle, *fresh)
	log.Fatal(r.Run(*addr))
}

// signUp gives a new account an id. A real app would check the name and keep its own record in
// Handlers.OnRegistered.
func signUp(_ *gin.Context, req ginpasskey.SignUp) (passkey.User, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return passkey.User{}, &apperr.Error{Code: "demo.name_required", Message: "type a name first", Cause: apperr.ErrInvalidInput}
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = name
	}
	return passkey.User{ID: hex.EncodeToString(id), Name: name, DisplayName: display}, nil
}
