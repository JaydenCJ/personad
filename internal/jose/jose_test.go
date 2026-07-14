// Tests for ordered JSON, key derivation, JWT signing and verification.
// The load-bearing property throughout is byte stability: same inputs must
// produce identical bytes on every run, every machine, every Go version.
package jose

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// --- ordered JSON ---------------------------------------------------------

func TestObjPreservesInsertionOrderAndOverwritesInPlace(t *testing.T) {
	o := NewObj().Set("z", 1).Set("a", 2).Set("m", 3)
	if got := string(o.Encode()); got != `{"z":1,"a":2,"m":3}` {
		t.Fatalf("got %s", got)
	}
	o.Set("a", 9)
	if got := string(o.Encode()); got != `{"z":1,"a":9,"m":3}` {
		t.Fatalf("overwrite moved the key: %s", got)
	}
}

func TestObjSetSortedIsDeterministic(t *testing.T) {
	// Go map iteration order is randomized; SetSorted must neutralize it.
	m := map[string]any{"zeta": 1, "alpha": 2, "mid": 3}
	first := string(NewObj().SetSorted(m).Encode())
	for i := 0; i < 20; i++ {
		if got := string(NewObj().SetSorted(m).Encode()); got != first {
			t.Fatalf("run %d differs: %s vs %s", i, got, first)
		}
	}
	if first != `{"alpha":2,"mid":3,"zeta":1}` {
		t.Fatalf("got %s", first)
	}
}

func TestObjNestedAndIndentedEncoding(t *testing.T) {
	inner := NewObj().Set("b", 2).Set("a", 1)
	o := NewObj().Set("outer", inner)
	if got := string(o.Encode()); got != `{"outer":{"b":2,"a":1}}` {
		t.Fatalf("got %s", got)
	}
	out := string(o.EncodeIndent())
	if !strings.HasSuffix(out, "}\n") {
		t.Fatalf("indent output should end with newline: %q", out)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("indent output is not valid JSON: %v", err)
	}
}

// --- base64url --------------------------------------------------------------

func TestB64RoundTripNoPadding(t *testing.T) {
	enc := B64([]byte{0xfb, 0xff, 0x00})
	if strings.Contains(enc, "=") || strings.ContainsAny(enc, "+/") {
		t.Fatalf("not base64url-unpadded: %q", enc)
	}
	dec, err := B64Decode(enc)
	if err != nil || string(dec) != "\xfb\xff\x00" {
		t.Fatalf("round trip failed: %q %v", dec, err)
	}
}

// --- Ed25519 signer -----------------------------------------------------------

func TestEdSignerKeyDerivationIsSeedBound(t *testing.T) {
	a, b := NewEdSigner("seed-1"), NewEdSigner("seed-1")
	if a.KID() != b.KID() {
		t.Fatalf("same seed produced different kids: %s vs %s", a.KID(), b.KID())
	}
	if NewEdSigner("seed-1").KID() == NewEdSigner("seed-2").KID() {
		t.Fatal("different seeds produced the same key")
	}
}

func TestEdSignerKIDIsStableAcrossReleases(t *testing.T) {
	// Pinned value: if this changes, every JWKS snapshot in every user's
	// test suite breaks. Changing key derivation is a breaking change.
	const want = "fgJG7O63p4GnVvlWDlg7orR72SxaXec4PYY23RhCydM"
	if got := NewEdSigner("ci-seed-1").KID(); got != want {
		t.Fatalf("kid drifted: got %s, want %s", got, want)
	}
}

func TestEdSignerSignVerify(t *testing.T) {
	s := NewEdSigner("seed")
	sig, err := s.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Verify([]byte("payload"), sig) {
		t.Fatal("valid signature rejected")
	}
	if s.Verify([]byte("tampered"), sig) {
		t.Fatal("signature verified over different message")
	}
}

func TestEdSignerJWKShapeAndJWKSWrapping(t *testing.T) {
	s := NewEdSigner("seed")
	jwk := s.PublicJWK()
	for _, k := range []string{"kty", "crv", "x", "kid", "use", "alg"} {
		if _, ok := jwk.Get(k); !ok {
			t.Errorf("JWK missing %q", k)
		}
	}
	if v, _ := jwk.Get("kty"); v != "OKP" {
		t.Errorf("kty = %v", v)
	}
	if v, _ := jwk.Get("alg"); v != "EdDSA" {
		t.Errorf("alg = %v", v)
	}
	doc := JWKS(s)
	keys, _ := doc.Get("keys")
	if len(keys.([]any)) != 1 {
		t.Fatalf("keys = %#v", keys)
	}
}

// --- RSA signer -----------------------------------------------------------------

func loadTestRSA(t *testing.T) *RSASigner {
	t.Helper()
	pemBytes, err := os.ReadFile("testdata/rsa_test_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadRSAPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRSASignerSignVerifyDeterministic(t *testing.T) {
	s := loadTestRSA(t)
	sig1, err := s.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	sig2, _ := s.Sign([]byte("payload"))
	if string(sig1) != string(sig2) {
		t.Fatal("PKCS#1 v1.5 signatures must be deterministic")
	}
	if !s.Verify([]byte("payload"), sig1) {
		t.Fatal("valid signature rejected")
	}
}

func TestRSASignerJWKShape(t *testing.T) {
	jwk := loadTestRSA(t).PublicJWK()
	if v, _ := jwk.Get("kty"); v != "RSA" {
		t.Errorf("kty = %v", v)
	}
	if v, _ := jwk.Get("alg"); v != "RS256" {
		t.Errorf("alg = %v", v)
	}
	n, _ := jwk.Get("n")
	if len(n.(string)) < 300 { // 2048-bit modulus ≈ 342 base64url chars
		t.Errorf("modulus looks too short: %d chars", len(n.(string)))
	}
}

func TestLoadRSAPEMRejectsGarbage(t *testing.T) {
	if _, err := LoadRSAPEM([]byte("not a pem")); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := LoadRSAPEM([]byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")); err == nil {
		t.Fatal("truncated key accepted")
	}
}

// --- JWT -------------------------------------------------------------------------

func TestSignJWTIsByteStable(t *testing.T) {
	s := NewEdSigner("seed")
	claims := func() *Obj { return NewObj().Set("iss", "http://127.0.0.1:9111").Set("sub", "u1") }
	t1, err := SignJWT(s, claims())
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := SignJWT(s, claims())
	if t1 != t2 {
		t.Fatalf("tokens differ:\n%s\n%s", t1, t2)
	}
}

func TestSignJWTHeaderOrder(t *testing.T) {
	s := NewEdSigner("seed")
	tok, _ := SignJWT(s, NewObj().Set("sub", "u1"))
	headerJSON, err := B64Decode(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	want := `{"alg":"EdDSA","kid":"` + s.KID() + `","typ":"JWT"}`
	if string(headerJSON) != want {
		t.Fatalf("header = %s, want %s", headerJSON, want)
	}
}

func TestVerifyJWTAcceptsOwnTokens(t *testing.T) {
	s := NewEdSigner("seed")
	tok, _ := SignJWT(s, NewObj().Set("sub", "u1").Set("n", 42))
	parsed, err := VerifyJWT(s, tok)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.StringClaim("sub") != "u1" {
		t.Errorf("sub = %q", parsed.StringClaim("sub"))
	}
	if parsed.IntClaim("n") != 42 {
		t.Errorf("n = %d", parsed.IntClaim("n"))
	}
}

func TestVerifyJWTRejectsForgeries(t *testing.T) {
	s := NewEdSigner("seed")
	tok, _ := SignJWT(s, NewObj().Set("sub", "u1"))
	parts := strings.Split(tok, ".")
	parts[1] = B64([]byte(`{"sub":"u2"}`))
	if _, err := VerifyJWT(s, strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered payload verified")
	}
	other, _ := SignJWT(NewEdSigner("seed-a"), NewObj().Set("sub", "u1"))
	if _, err := VerifyJWT(NewEdSigner("seed-b"), other); err == nil {
		t.Fatal("token from another key verified")
	}
}

func TestVerifyJWTRejectsAlgConfusion(t *testing.T) {
	// A token signed with RS256 must not verify against the EdDSA signer
	// even if someone hand-edits headers: alg and kid are both pinned.
	rsa := loadTestRSA(t)
	tok, _ := SignJWT(rsa, NewObj().Set("sub", "u1"))
	_, err := VerifyJWT(NewEdSigner("seed"), tok)
	if err == nil {
		t.Fatal("alg confusion accepted")
	}
	if !strings.Contains(err.Error(), "alg") {
		t.Fatalf("error should name the alg mismatch: %v", err)
	}
}

func TestDecodeJWT(t *testing.T) {
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!!.###.$$$"} {
		if _, err := DecodeJWT(bad); err == nil {
			t.Errorf("DecodeJWT(%q) accepted", bad)
		}
	}
	// exp timestamps near 2^53 lose precision as float64 in sloppy decoders;
	// json.Number keeps them exact.
	s := NewEdSigner("seed")
	tok, _ := SignJWT(s, NewObj().Set("exp", int64(9007199254740993)))
	parsed, err := DecodeJWT(tok)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.IntClaim("exp") != 9007199254740993 {
		t.Fatalf("exp = %d", parsed.IntClaim("exp"))
	}
}
