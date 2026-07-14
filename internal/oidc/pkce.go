// PKCE (RFC 7636) verification.
package oidc

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/JaydenCJ/personad/internal/jose"
)

// ValidChallengeMethod reports whether method is a supported
// code_challenge_method. The empty string defaults to "plain" per RFC 7636.
func ValidChallengeMethod(method string) bool {
	return method == "" || method == "plain" || method == "S256"
}

// ValidVerifier enforces the RFC 7636 §4.1 code_verifier grammar:
// 43–128 characters from the unreserved set.
func ValidVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// VerifyPKCE checks verifier against the challenge recorded at /authorize.
// Comparison is constant-time; a fake IdP still should not teach bad habits.
func VerifyPKCE(challenge, method, verifier string) bool {
	if !ValidVerifier(verifier) {
		return false
	}
	var derived string
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		derived = jose.B64(sum[:])
	case "plain", "":
		derived = verifier
	default:
		return false
	}
	return len(derived) == len(challenge) &&
		subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) == 1
}

// S256Challenge computes the S256 code_challenge for a verifier. Exported
// for tests and example scripts.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return jose.B64(sum[:])
}
