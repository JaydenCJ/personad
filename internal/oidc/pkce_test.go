// PKCE verification tests against RFC 7636's own test vector and the
// grammar rules clients most often get wrong.
package oidc

import (
	"strings"
	"testing"
)

// rfcVerifier/rfcChallenge are the worked example from RFC 7636 appendix B.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestS256MatchesRFCVectorAndVerifies(t *testing.T) {
	if got := S256Challenge(rfcVerifier); got != rfcChallenge {
		t.Fatalf("S256Challenge = %s, want %s", got, rfcChallenge)
	}
	if !VerifyPKCE(rfcChallenge, "S256", rfcVerifier) {
		t.Fatal("RFC vector rejected")
	}
	if VerifyPKCE(rfcChallenge, "S256", strings.Repeat("x", 43)) {
		t.Fatal("wrong verifier accepted")
	}
}

func TestVerifyPKCEPlainAndUnknownMethods(t *testing.T) {
	v := strings.Repeat("a", 43)
	if !VerifyPKCE(v, "plain", v) {
		t.Fatal("plain match rejected")
	}
	// Empty method defaults to plain per RFC 7636 §4.3.
	if !VerifyPKCE(v, "", v) {
		t.Fatal("default-plain match rejected")
	}
	if VerifyPKCE(v, "plain", strings.Repeat("b", 43)) {
		t.Fatal("plain mismatch accepted")
	}
	if VerifyPKCE(v, "S512", v) {
		t.Fatal("unknown method accepted")
	}
}

func TestValidVerifierGrammar(t *testing.T) {
	// Length bounds: RFC 7636 §4.1 says 43–128 characters.
	if ValidVerifier(strings.Repeat("a", 42)) {
		t.Error("42-char verifier accepted (min is 43)")
	}
	if !ValidVerifier(strings.Repeat("a", 43)) || !ValidVerifier(strings.Repeat("a", 128)) {
		t.Error("in-range verifier rejected")
	}
	if ValidVerifier(strings.Repeat("a", 129)) {
		t.Error("129-char verifier accepted (max is 128)")
	}
	// Charset: unreserved characters only.
	base := strings.Repeat("a", 42)
	for _, ok := range []string{base + "-", base + ".", base + "_", base + "~", base + "Z", base + "9"} {
		if !ValidVerifier(ok) {
			t.Errorf("verifier ending %q rejected", ok[len(ok)-1:])
		}
	}
	for _, bad := range []string{base + "+", base + "/", base + "=", base + " ", base + "é"} {
		if ValidVerifier(bad) {
			t.Errorf("verifier with %q accepted", bad[42:])
		}
	}
}

func TestSplitScope(t *testing.T) {
	got := SplitScope("openid  email openid groups email")
	if strings.Join(got, " ") != "openid email groups" {
		t.Fatalf("got %v", got)
	}
	if got := SplitScope("   "); got != nil {
		t.Fatalf("blank scope should be nil, got %v", got)
	}
}
