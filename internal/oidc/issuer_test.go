// Issuer tests: claim shaping, scope release rules, discovery metadata and
// the flagship guarantee — a frozen clock makes token bytes immutable,
// including one golden token pinned across releases.
package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/personad/internal/config"
	"github.com/JaydenCJ/personad/internal/jose"
)

// testTOML mirrors examples/personas.toml so golden values line up with the
// documented quickstart.
const testTOML = `
issuer = "http://127.0.0.1:9111"
seed = "ci-seed-1"

[tokens]
ttl = "1h"
issued_at = "2026-01-01T00:00:00Z"

[[clients]]
client_id = "web-app"
client_secret = "s3cret"
redirect_uris = ["http://127.0.0.1:3000/callback"]

[[clients]]
client_id = "spa"
redirect_uris = ["http://127.0.0.1:5173/callback"]

[[personas]]
name = "alice"
subject = "user-alice-001"
email = "alice@example.test"
email_verified = true
groups = ["admin", "dev"]

[personas.claims]
department = "engineering"
level = 5

[[personas]]
name = "bob"
subject = "user-bob-002"
email = "bob@example.test"
groups = ["dev"]
`

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	cfg, err := config.Load(testTOML)
	if err != nil {
		t.Fatal(err)
	}
	return NewIssuer(cfg, jose.NewEdSigner(cfg.Seed))
}

var allScopes = []string{"openid", "profile", "email", "groups"}

func TestIDTokenGoldenBytes(t *testing.T) {
	// The exact compact JWT for the documented example config. If this test
	// fails, users' snapshot tests fail too — treat any drift as breaking.
	const golden = "eyJhbGciOiJFZERTQSIsImtpZCI6ImZnSkc3TzYzcDRHblZ2bFdEbGc3b3JSNzJTeGFYZWM0UFlZMjNSaEN5ZE0iLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkxMTEiLCJzdWIiOiJ1c2VyLWFsaWNlLTAwMSIsImF1ZCI6IndlYi1hcHAiLCJleHAiOjE3NjcyMjkyMDAsImlhdCI6MTc2NzIyNTYwMCwiYXV0aF90aW1lIjoxNzY3MjI1NjAwLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUudGVzdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJkZXYiXSwiZGVwYXJ0bWVudCI6ImVuZ2luZWVyaW5nIiwibGV2ZWwiOjV9.eS_CBeCGZ2JR0Mtk1gZ0y3MXuEK4w_M-48mo3X913Q_tbQZtlOCg3N44ZS514RKY60Ovr-NKnh4PpEkdrFlQCw"
	iss := testIssuer(t)
	p, _ := iss.Cfg.Persona("alice")
	tok, err := iss.IDToken(p, "web-app", "", allScopes, iss.IssueTime())
	if err != nil {
		t.Fatal(err)
	}
	if tok != golden {
		t.Fatalf("golden token drifted:\n got %s\nwant %s", tok, golden)
	}
	// And re-minting cannot wobble.
	for i := 0; i < 10; i++ {
		again, _ := iss.IDToken(p, "web-app", "", allScopes, iss.IssueTime())
		if again != golden {
			t.Fatalf("mint %d differs", i)
		}
	}
}

func TestIDTokenRegisteredClaims(t *testing.T) {
	iss := testIssuer(t)
	p, _ := iss.Cfg.Persona("alice")
	tok, _ := iss.IDToken(p, "web-app", "nonce-1", allScopes, iss.IssueTime())
	parsed, err := jose.VerifyJWT(iss.Signer, tok)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.StringClaim("iss") != "http://127.0.0.1:9111" {
		t.Errorf("iss = %q", parsed.StringClaim("iss"))
	}
	if parsed.StringClaim("sub") != "user-alice-001" {
		t.Errorf("sub = %q", parsed.StringClaim("sub"))
	}
	if parsed.StringClaim("aud") != "web-app" {
		t.Errorf("aud = %q", parsed.StringClaim("aud"))
	}
	if parsed.StringClaim("nonce") != "nonce-1" {
		t.Errorf("nonce = %q", parsed.StringClaim("nonce"))
	}
	if parsed.IntClaim("exp")-parsed.IntClaim("iat") != 3600 {
		t.Errorf("exp-iat = %d, want 3600", parsed.IntClaim("exp")-parsed.IntClaim("iat"))
	}
	// Empty nonce must be omitted, not emitted as "".
	noNonce, _ := iss.IDToken(p, "web-app", "", allScopes, iss.IssueTime())
	decoded, _ := jose.DecodeJWT(noNonce)
	if _, ok := decoded.Claims["nonce"]; ok {
		t.Error("empty nonce claim emitted")
	}
}

func TestScopeReleaseRules(t *testing.T) {
	iss := testIssuer(t)
	p, _ := iss.Cfg.Persona("alice")
	at := iss.IssueTime()

	cases := []struct {
		scopes  []string
		present []string
		absent  []string
	}{
		{[]string{"openid"}, nil, []string{"email", "groups", "department"}},
		{[]string{"openid", "email"}, []string{"email", "email_verified"}, []string{"groups", "department"}},
		{[]string{"openid", "groups"}, []string{"groups"}, []string{"email", "department"}},
		{[]string{"openid", "profile"}, []string{"department", "level"}, []string{"email", "groups"}},
	}
	for _, c := range cases {
		tok, _ := iss.IDToken(p, "web-app", "", c.scopes, at)
		parsed, _ := jose.DecodeJWT(tok)
		for _, k := range c.present {
			if _, ok := parsed.Claims[k]; !ok {
				t.Errorf("scopes %v: claim %q missing", c.scopes, k)
			}
		}
		for _, k := range c.absent {
			if _, ok := parsed.Claims[k]; ok {
				t.Errorf("scopes %v: claim %q leaked", c.scopes, k)
			}
		}
	}
}

func TestAccessTokenShape(t *testing.T) {
	iss := testIssuer(t)
	p, _ := iss.Cfg.Persona("alice")
	tok, _ := iss.AccessToken(p, "web-app", allScopes, iss.IssueTime())
	parsed, err := jose.VerifyJWT(iss.Signer, tok)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.StringClaim("token_use") != "access" {
		t.Errorf("token_use = %q", parsed.StringClaim("token_use"))
	}
	if parsed.StringClaim("client_id") != "web-app" {
		t.Errorf("client_id = %q", parsed.StringClaim("client_id"))
	}
	if parsed.StringClaim("scope") != "openid profile email groups" {
		t.Errorf("scope = %q", parsed.StringClaim("scope"))
	}
	if len(parsed.StringClaim("jti")) != 24 {
		t.Errorf("jti = %q, want 24 hex chars", parsed.StringClaim("jti"))
	}
}

func TestAccessTokenDeterministicButInputBound(t *testing.T) {
	iss := testIssuer(t)
	p, _ := iss.Cfg.Persona("alice")
	at := iss.IssueTime()
	t1, _ := iss.AccessToken(p, "web-app", allScopes, at)
	t2, _ := iss.AccessToken(p, "web-app", allScopes, at)
	if t1 != t2 {
		t.Fatal("same inputs produced different access tokens")
	}
	t3, _ := iss.AccessToken(p, "web-app", allScopes, at.Add(time.Minute))
	if t1 == t3 {
		t.Fatal("different issue times produced the same token")
	}
}

func TestClientCredentialsTokenHasNoPersonaClaims(t *testing.T) {
	iss := testIssuer(t)
	tok, _ := iss.ClientCredentialsToken("web-app", []string{"api"}, iss.IssueTime())
	parsed, _ := jose.VerifyJWT(iss.Signer, tok)
	if parsed.StringClaim("sub") != "web-app" {
		t.Errorf("sub = %q, want the client_id", parsed.StringClaim("sub"))
	}
	for _, k := range []string{"email", "groups", "department"} {
		if _, ok := parsed.Claims[k]; ok {
			t.Errorf("persona claim %q leaked into a machine token", k)
		}
	}
}

func TestIssueTime(t *testing.T) {
	// Frozen by config:
	iss := testIssuer(t)
	want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !iss.IssueTime().Equal(want) {
		t.Fatalf("IssueTime = %v", iss.IssueTime())
	}
	// Live clock truncates to whole seconds (JWT iat granularity):
	cfg, _ := config.Load(strings.Replace(testTOML, "issued_at = \"2026-01-01T00:00:00Z\"\n", "", 1))
	live := NewIssuer(cfg, jose.NewEdSigner(cfg.Seed))
	fixed := time.Date(2026, 7, 1, 12, 34, 56, 789000000, time.UTC)
	live.Now = func() time.Time { return fixed }
	if got := live.IssueTime(); got != fixed.Truncate(time.Second) {
		t.Fatalf("IssueTime = %v", got)
	}
}

func TestDiscoveryDocument(t *testing.T) {
	iss := testIssuer(t)
	doc := iss.Discovery()
	get := func(k string) any { v, _ := doc.Get(k); return v }
	if get("issuer") != "http://127.0.0.1:9111" {
		t.Errorf("issuer = %v", get("issuer"))
	}
	if get("token_endpoint") != "http://127.0.0.1:9111/token" {
		t.Errorf("token_endpoint = %v", get("token_endpoint"))
	}
	if got := get("code_challenge_methods_supported").([]string); len(got) != 2 {
		t.Errorf("challenge methods = %v", got)
	}
	if got := get("id_token_signing_alg_values_supported").([]string); got[0] != "EdDSA" {
		t.Errorf("algs = %v", got)
	}
	// claims_supported aggregates persona claims and is sorted, so the
	// whole discovery document is snapshot-stable.
	claims := get("claims_supported").([]string)
	joined := strings.Join(claims, " ")
	for _, want := range []string{"sub", "email", "groups", "department", "level"} {
		if !strings.Contains(joined, want) {
			t.Errorf("claims_supported missing %q: %s", want, joined)
		}
	}
	for i := 1; i < len(claims); i++ {
		if claims[i] < claims[i-1] {
			t.Fatalf("claims_supported not sorted: %v", claims)
		}
	}
}
