// Signing keys. personad derives its Ed25519 key deterministically from the
// config seed (same seed → same key → same JWKS → byte-stable tokens on
// every machine), or loads an RSA key from PEM when a client library only
// speaks RS256. Both signature schemes are deterministic functions of
// (key, message), so either way identical input yields identical bytes.
package jose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// B64 encodes bytes as unpadded base64url, the JOSE alphabet.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// B64Decode decodes unpadded base64url.
func B64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Signer signs JWTs and can describe itself as a public JWK.
type Signer interface {
	// Alg returns the JOSE "alg" header value.
	Alg() string
	// KID returns the RFC 7638 thumbprint of the public key.
	KID() string
	// Sign returns the raw JWS signature over signingInput.
	Sign(signingInput []byte) ([]byte, error)
	// Verify reports whether sig is a valid signature over signingInput.
	Verify(signingInput, sig []byte) bool
	// PublicJWK returns the public key as an ordered JWK object.
	PublicJWK() *Obj
}

// --- Ed25519 --------------------------------------------------------------

// EdSigner is a deterministic Ed25519 signer.
type EdSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

// NewEdSigner derives an Ed25519 key from an arbitrary seed string. The
// derivation is a plain SHA-256, stable across Go versions and platforms —
// that stability is the whole point.
func NewEdSigner(seed string) *EdSigner {
	h := sha256.Sum256([]byte("personad-ed25519-v1:" + seed))
	priv := ed25519.NewKeyFromSeed(h[:])
	pub := priv.Public().(ed25519.PublicKey)
	s := &EdSigner{priv: priv, pub: pub}
	s.kid = thumbprint(fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, B64(pub)))
	return s
}

func (s *EdSigner) Alg() string { return "EdDSA" }
func (s *EdSigner) KID() string { return s.kid }

func (s *EdSigner) Sign(input []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, input), nil
}

func (s *EdSigner) Verify(input, sig []byte) bool {
	return ed25519.Verify(s.pub, input, sig)
}

func (s *EdSigner) PublicJWK() *Obj {
	return NewObj().
		Set("kty", "OKP").
		Set("crv", "Ed25519").
		Set("x", B64(s.pub)).
		Set("kid", s.kid).
		Set("use", "sig").
		Set("alg", "EdDSA")
}

// --- RSA (RS256) ----------------------------------------------------------

// RSASigner signs with RSASSA-PKCS1-v1_5 / SHA-256.
type RSASigner struct {
	priv *rsa.PrivateKey
	kid  string
}

// NewRSASigner wraps an existing RSA private key.
func NewRSASigner(priv *rsa.PrivateKey) *RSASigner {
	n := B64(priv.PublicKey.N.Bytes())
	e := B64(big.NewInt(int64(priv.PublicKey.E)).Bytes())
	kid := thumbprint(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n))
	return &RSASigner{priv: priv, kid: kid}
}

// LoadRSAPEM parses a PKCS#1 or PKCS#8 PEM-encoded RSA private key.
func LoadRSAPEM(pemBytes []byte) (*RSASigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in RSA key file")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return NewRSASigner(key), nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key file holds a %T, not an RSA private key", parsed)
	}
	return NewRSASigner(key), nil
}

func (s *RSASigner) Alg() string { return "RS256" }
func (s *RSASigner) KID() string { return s.kid }

func (s *RSASigner) Sign(input []byte) ([]byte, error) {
	sum := sha256.Sum256(input)
	// PKCS#1 v1.5 signatures are deterministic; rand is only consulted for
	// blinding and never changes the signature bytes.
	return rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, sum[:])
}

func (s *RSASigner) Verify(input, sig []byte) bool {
	sum := sha256.Sum256(input)
	return rsa.VerifyPKCS1v15(&s.priv.PublicKey, crypto.SHA256, sum[:], sig) == nil
}

func (s *RSASigner) PublicJWK() *Obj {
	return NewObj().
		Set("kty", "RSA").
		Set("n", B64(s.priv.PublicKey.N.Bytes())).
		Set("e", B64(big.NewInt(int64(s.priv.PublicKey.E)).Bytes())).
		Set("kid", s.kid).
		Set("use", "sig").
		Set("alg", "RS256")
}

// thumbprint implements RFC 7638: SHA-256 over the canonical JWK members
// (lexicographic order, no whitespace), base64url-encoded.
func thumbprint(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return B64(sum[:])
}

// JWKS renders the JWKS document for a set of signers.
func JWKS(signers ...Signer) *Obj {
	keys := make([]any, 0, len(signers))
	for _, s := range signers {
		keys = append(keys, s.PublicJWK())
	}
	return NewObj().Set("keys", keys)
}
