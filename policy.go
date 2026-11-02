package passkey

import (
	"errors"
	"slices"
	"time"
)

// Policy is the step-up policy: when a session must confirm with its passkey again. It starts as
// the policy fields of Config and can be changed while the Service runs with SetPolicy, for an app
// whose administrators change it.
type Policy struct {
	// ReconfirmAfter is how long a session may sit idle before it needs a confirmation
	// (CodeReconfirmRequired). 0 means never.
	ReconfirmAfter time.Duration
	// SensitiveActions are the action names that always need a recent confirmation.
	SensitiveActions []string
	// FreshFor is how long a confirmation counts for a sensitive action. 0 means the default, 5
	// minutes.
	FreshFor time.Duration
}

// policy is a Policy in use, with what is derived from it. It is never changed once built: a new
// policy is a new value, swapped in whole.
type policy struct {
	Policy
	touchEvery time.Duration
}

func newPolicy(p Policy, touchEvery time.Duration) (*policy, error) {
	if p.ReconfirmAfter < 0 || p.FreshFor < 0 {
		return nil, errors.New("passkey: a Policy duration cannot be negative")
	}
	if p.FreshFor == 0 {
		p.FreshFor = 5 * time.Minute
	}
	p.SensitiveActions = slices.Clone(p.SensitiveActions)
	if p.ReconfirmAfter > 0 && touchEvery >= p.ReconfirmAfter {
		touchEvery = p.ReconfirmAfter / 2
	}
	return &policy{Policy: p, touchEvery: touchEvery}, nil
}

// Policy is the policy in use. Its SensitiveActions are a copy.
func (s *Service) Policy() Policy {
	p := s.policy.Load().Policy
	p.SensitiveActions = slices.Clone(p.SensitiveActions)
	return p
}

// SetPolicy changes the policy while the Service runs. It is safe to call at any time, from any
// goroutine: each request reads one policy, the old or the new, never a mix. It takes effect at a
// session's next request: a lower ReconfirmAfter locks a session already idle longer than it, and a
// newly sensitive action needs a confirmation made within FreshFor. A negative duration is refused.
func (s *Service) SetPolicy(p Policy) error {
	np, err := newPolicy(p, s.cfg.TouchEvery)
	if err != nil {
		return err
	}
	s.policy.Store(np)
	return nil
}
