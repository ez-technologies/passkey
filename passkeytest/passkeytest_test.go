package passkeytest_test

import (
	"bytes"
	"testing"

	"github.com/ez-technologies/apperr"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/memstore"
	"github.com/ez-technologies/passkey/passkeytest"
)

const origin = "https://app.example.com"

func newService(t *testing.T) *passkey.Service {
	t.Helper()
	svc, err := passkey.New(passkey.Config{RPID: "app.example.com", RPName: "Example", Origins: []string{origin}}, memstore.New())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestTwoDevicesOneUser(t *testing.T) {
	ctx, svc := t.Context(), newService(t)
	laptop, phone := passkeytest.New(origin), passkeytest.New(origin)
	if _, err := passkeytest.SignUp(ctx, svc, laptop, passkey.User{ID: "u1", Name: "ada"}); err != nil {
		t.Fatal(err)
	}
	added, err := passkeytest.Register(ctx, svc, phone, passkey.User{ID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	// The same device cannot hold two passkeys of one user.
	if _, err := passkeytest.Register(ctx, svc, laptop, passkey.User{ID: "u1"}); err == nil {
		t.Fatal("a second passkey on the same device")
	}
	user, used, err := passkeytest.SignIn(ctx, svc, phone)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "u1" || !bytes.Equal(used.ID, added.ID) || len(phone.Credentials) != 1 {
		t.Fatalf("signed in as %+v with %x", user, used.ID)
	}
}

func TestAnotherServicesPasskeyIsRejected(t *testing.T) {
	ctx := t.Context()
	device := passkeytest.New(origin)
	if _, err := passkeytest.SignUp(ctx, newService(t), device, passkey.User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	_, _, err := passkeytest.SignIn(ctx, newService(t), device)
	if apperr.CodeOf(err) != passkey.CodeRejected {
		t.Fatalf("got %v, want %s", err, passkey.CodeRejected)
	}
}

func TestDeviceWithoutPasskey(t *testing.T) {
	if _, _, err := passkeytest.SignIn(t.Context(), newService(t), passkeytest.New(origin)); err == nil {
		t.Fatal("signed in with no passkey")
	}
}
