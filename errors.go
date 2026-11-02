package passkey

import (
	"errors"
	"net/http"

	"github.com/ez-technologies/apperr"
)

// Error codes. They are stable: a client can act on them (sign in again, confirm, retry) and word
// them in its own language. Every error the Service returns to a person carries one of them;
// read it with apperr.CodeOf.
const (
	// CodeSessionRequired: there is no session, or it ended. The client shows sign-in.
	CodeSessionRequired apperr.Code = "passkey.session_required"
	// CodeReconfirmRequired: the session was idle longer than the policy's ReconfirmAfter. The client
	// asks the person to confirm with their passkey (Confirm), then goes on.
	CodeReconfirmRequired apperr.Code = "passkey.reconfirm_required"
	// CodeConfirmationRequired: the action is sensitive and the last confirmation is older than
	// the policy's FreshFor. The answer carries the action's name in "action". The client confirms and
	// retries.
	CodeConfirmationRequired apperr.Code = "passkey.confirmation_required"
	// CodeRejected: the passkey was not accepted. One answer for every reason (unknown, removed,
	// bad signature, copied), so the answer tells nothing about who has a passkey.
	CodeRejected apperr.Code = "passkey.rejected"
	// CodeChallengeExpired: the ceremony took too long, was used already, or never existed.
	CodeChallengeExpired apperr.Code = "passkey.challenge_expired"
	// CodeInvalidCode: the one-time code is wrong, used or expired.
	CodeInvalidCode apperr.Code = "passkey.invalid_code"
	// CodeBadRequest: the request could not be read.
	CodeBadRequest apperr.Code = "passkey.bad_request"
)

func init() {
	apperr.Register(CodeSessionRequired, CodeReconfirmRequired, CodeConfirmationRequired,
		CodeRejected, CodeChallengeExpired, CodeInvalidCode, CodeBadRequest)
}

var (
	errSessionRequired = func() error { return apperr.New(CodeSessionRequired, "sign in first") }
	errReconfirm       = func() error { return apperr.New(CodeReconfirmRequired, "confirm it is you to go on") }
	errRejected        = func() error { return apperr.New(CodeRejected, "that passkey was not accepted") }
	errChallenge       = func() error { return apperr.New(CodeChallengeExpired, "that request has expired: start again") }
	errInvalidCode     = func() error { return apperr.New(CodeInvalidCode, "that code is not valid") }
)

func errConfirmation(action string) error {
	return apperr.New(CodeConfirmationRequired, "confirm it is you to do this").With("action", action)
}

// IsReconfirmRequired reports whether err means the session is locked for idleness.
func IsReconfirmRequired(err error) bool { return apperr.CodeOf(err) == CodeReconfirmRequired }

// HTTPStatus is the status an error is best answered with: 401 for no session or a locked one,
// 403 for a sensitive action that needs confirming, 400 for a bad request or expired challenge,
// and 500 for anything without a code of this package.
func HTTPStatus(err error) int {
	switch apperr.CodeOf(err) {
	case CodeSessionRequired, CodeReconfirmRequired, CodeRejected, CodeInvalidCode:
		return http.StatusUnauthorized
	case CodeConfirmationRequired:
		return http.StatusForbidden
	case CodeChallengeExpired, CodeBadRequest:
		return http.StatusBadRequest
	}
	if errors.Is(err, apperr.ErrInvalidInput) {
		return http.StatusBadRequest
	}
	if errors.Is(err, apperr.ErrForbidden) {
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}
