// Compact JWS (JWT) encoding and verification.
package jose

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SignJWT produces a compact JWT: base64url(header).base64url(claims).sig.
// The header is fixed to {"alg","kid","typ"} in that order, so the same
// signer and claims always yield the same bytes.
func SignJWT(s Signer, claims *Obj) (string, error) {
	header := NewObj().
		Set("alg", s.Alg()).
		Set("kid", s.KID()).
		Set("typ", "JWT")
	input := B64(header.Encode()) + "." + B64(claims.Encode())
	sig, err := s.Sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return input + "." + B64(sig), nil
}

// Token is a decoded (and, via VerifyJWT, authenticated) JWT.
type Token struct {
	Header map[string]any
	Claims map[string]any
	// SigningInput and Signature are retained for verification.
	signingInput string
	signature    []byte
}

// DecodeJWT splits and base64/JSON-decodes a compact JWT without verifying
// the signature. Numeric claims decode as json.Number to avoid float drift.
func DecodeJWT(token string) (*Token, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt must have 3 dot-separated parts, has %d", len(parts))
	}
	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt header: %w", err)
	}
	claims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt claims: %w", err)
	}
	sig, err := B64Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt signature: %w", err)
	}
	return &Token{
		Header:       header,
		Claims:       claims,
		signingInput: parts[0] + "." + parts[1],
		signature:    sig,
	}, nil
}

// VerifyJWT decodes token and checks its signature against s, including
// that the header alg and kid match (an alg-confusion guard, small as this
// provider is).
func VerifyJWT(s Signer, token string) (*Token, error) {
	t, err := DecodeJWT(token)
	if err != nil {
		return nil, err
	}
	if alg, _ := t.Header["alg"].(string); alg != s.Alg() {
		return nil, fmt.Errorf("jwt alg %q does not match issuer alg %q", t.Header["alg"], s.Alg())
	}
	if kid, _ := t.Header["kid"].(string); kid != s.KID() {
		return nil, errors.New("jwt kid does not match the issuer key")
	}
	if !s.Verify([]byte(t.signingInput), t.signature) {
		return nil, errors.New("jwt signature verification failed")
	}
	return t, nil
}

// StringClaim returns claim name as a string ("" when absent or non-string).
func (t *Token) StringClaim(name string) string {
	s, _ := t.Claims[name].(string)
	return s
}

// IntClaim returns claim name as an int64, or 0 when absent/non-numeric.
func (t *Token) IntClaim(name string) int64 {
	n, ok := t.Claims[name].(json.Number)
	if !ok {
		return 0
	}
	v, err := n.Int64()
	if err != nil {
		return 0
	}
	return v
}

func decodeSegment(seg string) (map[string]any, error) {
	raw, err := B64Decode(seg)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}
