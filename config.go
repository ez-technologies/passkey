package passkey

import (
	"errors"
	"net/http"
	"time"
)

// Config is everything the library needs to know. Only RPID, RPName and Origins are required; the
// rest have defaults (see the field comments).
type Config struct {
	// RPID is the relying-party id: the domain passkeys belong to, such as "example.com". It is
	// part of every passkey, so changing it later means everyone registers again.
	RPID string
	// RPName is the name the device shows when it makes a passkey.
	RPName string
	// Origins are the full origins the browser may call from, such as "https://example.com".
	Origins []string

	// Cookie sets the session cookie.
	Cookie CookieConfig
	// SessionLifetime is the most a session lives from sign-in. Default 30 days.
	SessionLifetime time.Duration

	// ReconfirmAfter, SensitiveActions and FreshFor are the step-up policy the Service starts with;
	// Service.SetPolicy changes it while the Service runs.

	// ReconfirmAfter is how long a session may sit idle before the person confirms with their
	// passkey again (CodeReconfirmRequired). 0 means never.
	ReconfirmAfter time.Duration
	// SensitiveActions are action names (such as "device.add" or "member.approve") that always
	// need a recent confirmation. RequireFresh refuses them with CodeConfirmationRequired when the
	// last confirmation is older than FreshFor. Any name not listed passes.
	SensitiveActions []string
	// FreshFor is how long a confirmation counts as fresh for a sensitive action. Default 5 minutes.
	FreshFor time.Duration

	// ChallengeTimeout is how long a ceremony may take between begin and finish. Default 5 minutes.
	ChallengeTimeout time.Duration
	// TouchEvery is how rarely a session's LastActiveAt is written: at most once per this long.
	// Default 1 minute. When it is not shorter than ReconfirmAfter, half of ReconfirmAfter is used.
	TouchEvery time.Duration
	// CodeLength is the number of characters of a one-time code. Default 10 (about 49 bits).
	CodeLength int

	// Now returns the current time. Default time.Now; tests set it.
	Now func() time.Time
}

// CookieConfig sets the session cookie. The cookie is always HttpOnly.
type CookieConfig struct {
	// Name of the cookie. Default "passkey_session".
	Name string
	// Path of the cookie. Default "/".
	Path string
	// Domain of the cookie. Default empty: the host that set it.
	Domain string
	// Insecure drops the Secure attribute. Browsers accept Secure cookies on http://localhost,
	// so this is needed only for plain HTTP on another host name.
	Insecure bool
	// SameSite of the cookie. Default http.SameSiteLaxMode.
	SameSite http.SameSite
}

func (c *Config) withDefaults() (Config, error) {
	out := *c
	if out.RPID == "" || out.RPName == "" || len(out.Origins) == 0 {
		return out, errors.New("passkey: Config needs RPID, RPName and Origins")
	}
	if out.Cookie.Name == "" {
		out.Cookie.Name = "passkey_session"
	}
	if out.Cookie.Path == "" {
		out.Cookie.Path = "/"
	}
	if out.Cookie.SameSite == 0 {
		out.Cookie.SameSite = http.SameSiteLaxMode
	}
	if out.SessionLifetime <= 0 {
		out.SessionLifetime = 30 * 24 * time.Hour
	}
	if out.ReconfirmAfter < 0 {
		out.ReconfirmAfter = 0
	}
	if out.FreshFor <= 0 {
		out.FreshFor = 5 * time.Minute
	}
	if out.ChallengeTimeout <= 0 {
		out.ChallengeTimeout = 5 * time.Minute
	}
	if out.TouchEvery <= 0 {
		out.TouchEvery = time.Minute
	}
	if out.CodeLength <= 0 {
		out.CodeLength = 10
	}
	if out.Now == nil {
		out.Now = time.Now
	}
	return out, nil
}
