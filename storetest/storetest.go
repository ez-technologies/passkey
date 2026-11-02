// Package storetest checks that a passkey.Store behaves the way the library relies on. Run it from
// a test of your own store:
//
//	func TestMyStore(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) passkey.Store { return newEmptyStore(t) })
//	}
//
// The factory is called once per sub-test and must return an empty store.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ez-technologies/passkey"
)

// Run runs every check against stores made by newStore.
func Run(t *testing.T, newStore func(t *testing.T) passkey.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	t.Run("users", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.UserByID(ctx, "u1"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("UserByID of a missing user: got %v, want ErrNotFound", err)
		}
		u := &passkey.User{ID: "u1", Handle: []byte{1, 2, 3}, Name: "ada", DisplayName: "Ada"}
		mustDo(t, s.SaveUser(ctx, u))
		got, err := s.UserByID(ctx, "u1")
		mustDo(t, err)
		if got.Name != "ada" || got.DisplayName != "Ada" || !bytes.Equal(got.Handle, u.Handle) {
			t.Fatalf("UserByID: got %+v", got)
		}
		got, err = s.UserByHandle(ctx, []byte{1, 2, 3})
		mustDo(t, err)
		if got.ID != "u1" {
			t.Fatalf("UserByHandle: got %+v", got)
		}
		if _, err := s.UserByHandle(ctx, []byte{9}); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("UserByHandle of a missing handle: got %v, want ErrNotFound", err)
		}
		u.DisplayName = "Ada L."
		mustDo(t, s.SaveUser(ctx, u))
		got, err = s.UserByID(ctx, "u1")
		mustDo(t, err)
		if got.DisplayName != "Ada L." {
			t.Fatalf("SaveUser did not update: got %+v", got)
		}
	})

	t.Run("credentials", func(t *testing.T) {
		s := newStore(t)
		mustDo(t, s.SaveUser(ctx, &passkey.User{ID: "u1", Handle: []byte{1}, Name: "a", DisplayName: "a"}))
		list, err := s.Credentials(ctx, "u1")
		mustDo(t, err)
		if list == nil || len(list) != 0 {
			t.Fatalf("Credentials of a user with none: got %#v, want an empty list", list)
		}
		c1 := &passkey.Credential{ID: []byte("c1"), UserID: "u1", PublicKey: []byte("pk1"), SignCount: 1,
			Transports: []string{"internal", "hybrid"}, AAGUID: []byte{7}, BackupEligible: true, Name: "Laptop",
			CreatedAt: now, LastUsedAt: now}
		c2 := &passkey.Credential{ID: []byte("c2"), UserID: "u1", PublicKey: []byte("pk2"), Name: "Phone",
			CreatedAt: now.Add(time.Second), LastUsedAt: now.Add(time.Second)}
		mustDo(t, s.AddCredential(ctx, c1))
		mustDo(t, s.AddCredential(ctx, c2))
		list, err = s.Credentials(ctx, "u1")
		mustDo(t, err)
		if len(list) != 2 || !bytes.Equal(list[0].ID, c1.ID) || !bytes.Equal(list[1].ID, c2.ID) {
			t.Fatalf("Credentials: want c1, c2 oldest first, got %d", len(list))
		}
		g := list[0]
		if !bytes.Equal(g.PublicKey, c1.PublicKey) || g.SignCount != 1 || len(g.Transports) != 2 ||
			g.Transports[1] != "hybrid" || !bytes.Equal(g.AAGUID, c1.AAGUID) || !g.BackupEligible || g.Name != "Laptop" {
			t.Fatalf("Credentials did not keep the fields: %+v", g)
		}
		c1.SignCount, c1.BackupState, c1.LastUsedAt = 5, true, now.Add(time.Hour)
		mustDo(t, s.UpdateCredential(ctx, c1))
		list, _ = s.Credentials(ctx, "u1")
		if list[0].SignCount != 5 || !list[0].BackupState || !list[0].LastUsedAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("UpdateCredential: got %+v", list[0])
		}
		if err := s.DeleteCredential(ctx, "someone-else", c1.ID); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("DeleteCredential of another user's credential: got %v, want ErrNotFound", err)
		}
		mustDo(t, s.DeleteCredential(ctx, "u1", c1.ID))
		list, _ = s.Credentials(ctx, "u1")
		if len(list) != 1 || !bytes.Equal(list[0].ID, c2.ID) {
			t.Fatalf("DeleteCredential: %d left", len(list))
		}
	})

	t.Run("sessions", func(t *testing.T) {
		s := newStore(t)
		sess := &passkey.Session{ID: "h1", UserID: "u1", CredentialID: []byte("c1"), CreatedAt: now,
			ExpiresAt: now.Add(time.Hour), LastActiveAt: now, ConfirmedAt: now}
		mustDo(t, s.CreateSession(ctx, sess))
		mustDo(t, s.CreateSession(ctx, &passkey.Session{ID: "h2", UserID: "u1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now, ConfirmedAt: now}))
		mustDo(t, s.CreateSession(ctx, &passkey.Session{ID: "h3", UserID: "u2", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now, ConfirmedAt: now}))
		got, err := s.GetSession(ctx, "h1")
		mustDo(t, err)
		if got.UserID != "u1" || !bytes.Equal(got.CredentialID, []byte("c1")) || !got.ExpiresAt.Equal(sess.ExpiresAt) {
			t.Fatalf("GetSession: got %+v", got)
		}
		sess.LastActiveAt, sess.ConfirmedAt = now.Add(time.Minute), now.Add(2*time.Minute)
		mustDo(t, s.TouchSession(ctx, sess))
		got, _ = s.GetSession(ctx, "h1")
		if !got.LastActiveAt.Equal(now.Add(time.Minute)) || !got.ConfirmedAt.Equal(now.Add(2*time.Minute)) {
			t.Fatalf("TouchSession: got %+v", got)
		}
		mustDo(t, s.DeleteSession(ctx, "h1"))
		if _, err := s.GetSession(ctx, "h1"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("GetSession after delete: got %v, want ErrNotFound", err)
		}
		mustDo(t, s.DeleteUserSessions(ctx, "u1"))
		if _, err := s.GetSession(ctx, "h2"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("DeleteUserSessions left a session")
		}
		if _, err := s.GetSession(ctx, "h3"); err != nil {
			t.Fatalf("DeleteUserSessions removed another user's session: %v", err)
		}
	})

	t.Run("challenges work once", func(t *testing.T) {
		s := newStore(t)
		ch := &passkey.Challenge{ID: "x", Kind: "login", UserID: "u1", Data: []byte(`{"a":1}`), ExpiresAt: now.Add(time.Minute)}
		mustDo(t, s.SaveChallenge(ctx, ch))
		got, err := s.TakeChallenge(ctx, "x")
		mustDo(t, err)
		if got.Kind != "login" || got.UserID != "u1" || string(got.Data) != `{"a":1}` || !got.ExpiresAt.Equal(ch.ExpiresAt) {
			t.Fatalf("TakeChallenge: got %+v", got)
		}
		if _, err := s.TakeChallenge(ctx, "x"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("a second TakeChallenge: got %v, want ErrNotFound", err)
		}
	})

	t.Run("challenge taken by one of many at once", func(t *testing.T) {
		s := newStore(t)
		mustDo(t, s.SaveChallenge(ctx, &passkey.Challenge{ID: "y", Kind: "login", Data: []byte(`{}`), ExpiresAt: now.Add(time.Minute)}))
		if wins := race(func() error { _, err := s.TakeChallenge(ctx, "y"); return err }); wins != 1 {
			t.Fatalf("%d callers took the same challenge, want 1", wins)
		}
	})

	t.Run("codes redeem once", func(t *testing.T) {
		s := newStore(t)
		mustDo(t, s.CreateCode(ctx, &passkey.Code{Hash: "c", UserID: "u1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
		if _, err := s.RedeemCode(ctx, "other", now); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("RedeemCode of a wrong code: got %v", err)
		}
		got, err := s.RedeemCode(ctx, "c", now)
		mustDo(t, err)
		if got.UserID != "u1" {
			t.Fatalf("RedeemCode: got %+v", got)
		}
		if _, err := s.RedeemCode(ctx, "c", now); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("a second RedeemCode: got %v, want ErrNotFound", err)
		}
	})

	t.Run("expired code", func(t *testing.T) {
		s := newStore(t)
		mustDo(t, s.CreateCode(ctx, &passkey.Code{Hash: "e", UserID: "u1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
		if _, err := s.RedeemCode(ctx, "e", now.Add(time.Hour)); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("RedeemCode at its expiry: got %v, want ErrNotFound", err)
		}
	})

	t.Run("code redeemed by one of many at once", func(t *testing.T) {
		s := newStore(t)
		mustDo(t, s.CreateCode(ctx, &passkey.Code{Hash: "r", UserID: "u1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
		if wins := race(func() error { _, err := s.RedeemCode(ctx, "r", now); return err }); wins != 1 {
			t.Fatalf("%d callers redeemed the same code, want 1", wins)
		}
	})
}

func race(f func() error) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f() == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return wins
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
