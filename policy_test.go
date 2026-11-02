package passkey_test

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ez-technologies/passkey"
)

func TestSetPolicySensitiveActions(t *testing.T) {
	h := newHarness(t, nil)
	r, _ := h.startSession("u1", nil)
	sess, err := h.svc.Session(h.ctx, r)
	must(t, err)
	h.wait(10 * time.Minute)
	must(t, h.svc.CheckFresh(sess, "member.approve"))

	must(t, h.svc.SetPolicy(passkey.Policy{SensitiveActions: []string{"member.approve"}, FreshFor: 5 * time.Minute}))
	if !h.svc.IsSensitive("member.approve") {
		t.Fatal("the new sensitive action is not sensitive")
	}
	wantCode(t, h.svc.CheckFresh(sess, "member.approve"), passkey.CodeConfirmationRequired)
	must(t, h.svc.SetPolicy(passkey.Policy{SensitiveActions: []string{"member.approve"}, FreshFor: time.Hour}))
	must(t, h.svc.CheckFresh(sess, "member.approve"))

	must(t, h.svc.SetPolicy(passkey.Policy{}))
	must(t, h.svc.CheckFresh(sess, "member.approve"))
}

func TestSetPolicyReconfirmAfter(t *testing.T) {
	h := newHarness(t, nil)
	r, _ := h.startSession("u1", nil)
	h.wait(20 * time.Minute)
	must(t, h.svc.SetPolicy(passkey.Policy{ReconfirmAfter: 10 * time.Minute}))
	_, err := h.svc.Session(h.ctx, r)
	wantCode(t, err, passkey.CodeReconfirmRequired)
	// Lifting the lock policy unlocks the session.
	must(t, h.svc.SetPolicy(passkey.Policy{}))
	_, err = h.svc.Session(h.ctx, r)
	must(t, err)
	// A live session is touched often enough for the new interval.
	must(t, h.svc.SetPolicy(passkey.Policy{ReconfirmAfter: 30 * time.Second}))
	if got := h.svc.Config().TouchEvery; got != 15*time.Second {
		t.Fatalf("TouchEvery %v, want 15s", got)
	}
	for range 4 {
		h.wait(20 * time.Second)
		_, err = h.svc.Session(h.ctx, r)
		must(t, err)
	}
}

func TestPolicyIsCopied(t *testing.T) {
	actions := []string{"a"}
	h := newHarness(t, func(c *passkey.Config) { c.SensitiveActions = actions; c.ReconfirmAfter = time.Hour })
	actions[0] = "changed"
	p := h.svc.Policy()
	if !slices.Equal(p.SensitiveActions, []string{"a"}) || p.ReconfirmAfter != time.Hour || p.FreshFor != 5*time.Minute {
		t.Fatalf("policy %+v", p)
	}
	p.SensitiveActions[0] = "changed"
	set := []string{"b"}
	must(t, h.svc.SetPolicy(passkey.Policy{SensitiveActions: set}))
	set[0] = "changed"
	if p := h.svc.Policy(); !slices.Equal(p.SensitiveActions, []string{"b"}) || p.FreshFor != 5*time.Minute {
		t.Fatalf("policy %+v", p)
	}
	if c := h.svc.Config(); !slices.Equal(c.SensitiveActions, []string{"b"}) || c.ReconfirmAfter != 0 || c.TouchEvery != time.Minute {
		t.Fatalf("config %+v", c)
	}
}

func TestSetPolicyRefusesNegative(t *testing.T) {
	h := newHarness(t, func(c *passkey.Config) { c.SensitiveActions = []string{"a"} })
	if err := h.svc.SetPolicy(passkey.Policy{ReconfirmAfter: -time.Second}); err == nil {
		t.Fatal("a negative ReconfirmAfter was accepted")
	}
	if err := h.svc.SetPolicy(passkey.Policy{FreshFor: -time.Second}); err == nil {
		t.Fatal("a negative FreshFor was accepted")
	}
	if !h.svc.IsSensitive("a") {
		t.Fatal("a refused policy replaced the one in use")
	}
}

// Run with -race: SetPolicy while requests read the policy.
func TestSetPolicyConcurrently(t *testing.T) {
	h := newHarness(t, nil)
	r, _ := h.startSession("u1", nil)
	sess, err := h.svc.Session(h.ctx, r)
	must(t, err)
	policies := []passkey.Policy{
		{},
		{ReconfirmAfter: time.Hour, SensitiveActions: []string{"member.approve"}, FreshFor: time.Hour},
		{ReconfirmAfter: time.Minute, SensitiveActions: []string{"member.approve", "device.add"}},
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := range 200 {
				if err := h.svc.SetPolicy(policies[(i+j)%len(policies)]); err != nil {
					t.Error(err)
					return
				}
			}
		})
		wg.Go(func() {
			for range 200 {
				if _, err := h.svc.Session(h.ctx, r); err != nil {
					t.Error(err)
					return
				}
				// Fresh under every policy: the session was just started.
				if err := h.svc.CheckFresh(sess, "member.approve"); err != nil {
					t.Error(err)
					return
				}
				_ = h.svc.IsSensitive("device.add")
				_ = h.svc.Policy()
				_ = h.svc.Config()
			}
		})
	}
	wg.Wait()
}
