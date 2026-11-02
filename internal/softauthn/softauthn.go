// Package softauthn is a software passkey authenticator for tests: it answers the options a server
// sends with the JSON a browser would send back, as @simplewebauthn/browser does.
package softauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var b64 = base64.RawURLEncoding

// Credential is a passkey held by the authenticator.
type Credential struct {
	ID         []byte
	Key        *ecdsa.PrivateKey
	RPID       string
	UserHandle []byte
	SignCount  uint32
}

// Authenticator holds passkeys and signs for one origin.
type Authenticator struct {
	Origin      string
	Credentials []*Credential
}

// New makes an authenticator that answers as origin.
func New(origin string) *Authenticator { return &Authenticator{Origin: origin} }

type creationOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	Exclude []struct {
		ID string `json:"id"`
	} `json:"excludeCredentials"`
}

type requestOptions struct {
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	Allow     []struct {
		ID string `json:"id"`
	} `json:"allowCredentials"`
}

func (a *Authenticator) clientData(kind, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

// Register answers registration options with a new passkey.
func (a *Authenticator) Register(optionsJSON []byte) ([]byte, error) {
	var o creationOptions
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	for _, ex := range o.Exclude {
		for _, c := range a.Credentials {
			if ex.ID == b64.EncodeToString(c.ID) {
				return nil, errors.New("softauthn: this authenticator already has a passkey of that user")
			}
		}
	}
	handle, err := b64.DecodeString(o.User.ID)
	if err != nil {
		return nil, fmt.Errorf("softauthn: user id: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	cred := &Credential{ID: id, Key: key, RPID: o.RP.ID, UserHandle: handle}

	pub, err := key.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	raw := pub.Bytes() // 0x04 || X || Y
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		return nil, err
	}
	var auth bytes.Buffer
	rpHash := sha256.Sum256([]byte(o.RP.ID))
	auth.Write(rpHash[:])
	auth.WriteByte(0x01 | 0x04 | 0x40) // user present, user verified, attested credential data
	_ = binary.Write(&auth, binary.BigEndian, uint32(0))
	auth.Write(make([]byte, 16)) // AAGUID
	_ = binary.Write(&auth, binary.BigEndian, uint16(len(id)))
	auth.Write(id)
	auth.Write(cose)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth.Bytes()})
	if err != nil {
		return nil, err
	}
	a.Credentials = append(a.Credentials, cred)
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(id), "rawId": b64.EncodeToString(id), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.Challenge)),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal"},
		},
	})
}

// SignIn answers sign-in options with the first passkey that fits them (any passkey of the relying
// party when the options name none).
func (a *Authenticator) SignIn(optionsJSON []byte) ([]byte, error) {
	var o requestOptions
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	var cred *Credential
	for _, c := range a.Credentials {
		if c.RPID != o.RPID {
			continue
		}
		if len(o.Allow) == 0 {
			cred = c
			break
		}
		for _, al := range o.Allow {
			if al.ID == b64.EncodeToString(c.ID) {
				cred = c
			}
		}
		if cred != nil {
			break
		}
	}
	if cred == nil {
		return nil, errors.New("softauthn: no passkey for these options")
	}
	cred.SignCount++
	var auth bytes.Buffer
	rpHash := sha256.Sum256([]byte(cred.RPID))
	auth.Write(rpHash[:])
	auth.WriteByte(0x01 | 0x04)
	_ = binary.Write(&auth, binary.BigEndian, cred.SignCount)
	cd := a.clientData("webauthn.get", o.Challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(bytes.Clone(auth.Bytes()), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.Key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(cred.ID), "rawId": b64.EncodeToString(cred.ID), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(auth.Bytes()),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(cred.UserHandle),
		},
	})
}
