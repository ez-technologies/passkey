package passkeytest_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"time"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/memstore"
	"github.com/ez-technologies/passkey/passkeytest"
)

// A test of your app signs a user up, signs them in and confirms a sensitive action, all in Go.
func Example() {
	ctx := context.Background()
	now := time.Now()
	svc, err := passkey.New(passkey.Config{
		RPID: "example.com", RPName: "Example", Origins: []string{"https://example.com"},
		SensitiveActions: []string{"member.approve"},
		Now:              func() time.Time { return now },
	}, memstore.New())
	if err != nil {
		panic(err)
	}
	laptop := passkeytest.New("https://example.com")

	cred, err := passkeytest.SignUp(ctx, svc, laptop, passkey.User{ID: "u1", Name: "ada", DisplayName: "Ada"})
	fmt.Println("signed up:", cred.UserID, err)

	user, cred, err := passkeytest.SignIn(ctx, svc, laptop)
	fmt.Println("signed in:", user.DisplayName, err)

	sess, _ := svc.StartSession(ctx, httptest.NewRecorder(), user.ID, cred.ID)
	now = now.Add(10 * time.Minute) // the sign-in is no longer fresh
	fmt.Println("approve:", passkey.HTTPStatus(svc.CheckFresh(sess, "member.approve")))

	err = passkeytest.Confirm(ctx, svc, laptop, sess)
	fmt.Println("confirmed:", err, "approve:", svc.CheckFresh(sess, "member.approve"))

	// Output:
	// signed up: u1 <nil>
	// signed in: Ada <nil>
	// approve: 403
	// confirmed: <nil> approve: <nil>
}
