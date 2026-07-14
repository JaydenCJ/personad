// Tests for persona-file loading and validation. The validator is the last
// line of defense between a typo'd CI fixture and a token that silently
// lacks the claim a test expects, so rejections matter as much as accepts.
package config

import (
	"strings"
	"testing"
	"time"
)

// minimalTOML is the smallest valid persona file; tests mutate it.
const minimalTOML = `
issuer = "http://127.0.0.1:9111"
seed = "test-seed"

[[clients]]
client_id = "app"
client_secret = "secret"
redirect_uris = ["http://127.0.0.1:3000/cb"]

[[personas]]
name = "alice"
subject = "user-1"
`

func load(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := Load(src)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	return cfg
}

func loadErr(t *testing.T, src, wantSubstr string) {
	t.Helper()
	_, err := Load(src)
	if err == nil {
		t.Fatalf("Load unexpectedly succeeded (wanted error mentioning %q)", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("error %q does not mention %q", err, wantSubstr)
	}
}

func TestLoadMinimalConfigAppliesDefaults(t *testing.T) {
	cfg := load(t, minimalTOML)
	if cfg.Algorithm != "EdDSA" {
		t.Errorf("default algorithm = %q, want EdDSA", cfg.Algorithm)
	}
	if cfg.TTL != time.Hour {
		t.Errorf("default TTL = %v, want 1h", cfg.TTL)
	}
	if cfg.IssuedAt != nil {
		t.Error("IssuedAt should default to nil (live clock)")
	}
}

func TestLoadFullPersona(t *testing.T) {
	src := minimalTOML + `
email = "alice@example.test"
email_verified = true
groups = ["admin", "dev"]

[personas.claims]
department = "engineering"
level = 5
tags = ["a", "b"]
`
	cfg := load(t, src)
	p, ok := cfg.Persona("alice")
	if !ok {
		t.Fatal("persona alice missing")
	}
	if p.Email != "alice@example.test" || !p.EmailVerified {
		t.Errorf("email fields wrong: %+v", p)
	}
	if len(p.Groups) != 2 || p.Groups[0] != "admin" {
		t.Errorf("groups wrong: %v", p.Groups)
	}
	if p.Claims["level"] != int64(5) {
		t.Errorf("claims wrong: %#v", p.Claims)
	}
	if got := p.SortedClaimKeys(); strings.Join(got, ",") != "department,level,tags" {
		t.Errorf("SortedClaimKeys = %v", got)
	}
}

func TestTokensSection(t *testing.T) {
	cfg := load(t, minimalTOML+"\n[tokens]\nttl = \"90m\"\nissued_at = \"2026-01-01T09:00:00+09:00\"\n")
	if cfg.TTL != 90*time.Minute {
		t.Errorf("TTL = %v", cfg.TTL)
	}
	if cfg.IssuedAt == nil {
		t.Fatal("IssuedAt not set")
	}
	// Must be normalized to UTC so token bytes do not depend on the zone
	// spelling in the file.
	if got := cfg.IssuedAt.Format(time.RFC3339); got != "2026-01-01T00:00:00Z" {
		t.Errorf("IssuedAt = %s, want UTC-normalized", got)
	}
}

func TestTokensSectionRejections(t *testing.T) {
	loadErr(t, minimalTOML+"\n[tokens]\nttl = \"-5m\"\n", "positive duration")
	loadErr(t, minimalTOML+"\n[tokens]\nttl = \"soon\"\n", "positive duration")
	loadErr(t, minimalTOML+"\n[tokens]\nissued_at = \"yesterday\"\n", "RFC 3339")
}

func TestIssuerAndSeedValidation(t *testing.T) {
	loadErr(t, strings.Replace(minimalTOML, `issuer = "http://127.0.0.1:9111"`, "", 1), "issuer is required")
	loadErr(t, strings.Replace(minimalTOML, "http://127.0.0.1:9111", "127.0.0.1:9111", 1), "absolute http(s) URL")
	// OIDC discovery concatenates path segments onto the issuer; a trailing
	// slash produces double-slash URLs that some client libraries reject.
	loadErr(t, strings.Replace(minimalTOML, "http://127.0.0.1:9111", "http://127.0.0.1:9111/", 1), "must not end with a slash")
	loadErr(t, strings.Replace(minimalTOML, `seed = "test-seed"`, "", 1), "seed is required")
}

func TestAlgorithmValidation(t *testing.T) {
	loadErr(t, minimalTOML+"\n[tokens]\nalgorithm = \"HS256\"\n", "not supported")
	loadErr(t, minimalTOML+"\n[tokens]\nalgorithm = \"RS256\"\n", "requires tokens.rsa_key_file")
	loadErr(t, minimalTOML+"\n[tokens]\nrsa_key_file = \"k.pem\"\n", "only used with")
}

func TestClientValidation(t *testing.T) {
	noClients := `
issuer = "http://127.0.0.1:9111"
seed = "s"
[[personas]]
name = "alice"
subject = "user-1"
`
	loadErr(t, noClients, "at least one [[clients]]")
	dup := minimalTOML + "\n[[clients]]\nclient_id = \"app\"\nredirect_uris = [\"http://127.0.0.1:3000/cb\"]\n"
	loadErr(t, dup, `client_id "app" is defined twice`)
	loadErr(t, strings.Replace(minimalTOML, `redirect_uris = ["http://127.0.0.1:3000/cb"]`, "", 1),
		"at least one redirect_uris")
}

func TestRedirectURIValidation(t *testing.T) {
	loadErr(t, strings.Replace(minimalTOML, "http://127.0.0.1:3000/cb", "/cb", 1), "not an absolute URL")
	loadErr(t, strings.Replace(minimalTOML, "http://127.0.0.1:3000/cb", "http://127.0.0.1:3000/cb#frag", 1),
		"must not contain a fragment")
}

func TestRedirectAllowedIsExactMatch(t *testing.T) {
	cfg := load(t, minimalTOML)
	cl, _ := cfg.Client("app")
	if !cl.RedirectAllowed("http://127.0.0.1:3000/cb") {
		t.Error("registered URI rejected")
	}
	// Prefix and superstring matches are classic redirect-validation bugs.
	if cl.RedirectAllowed("http://127.0.0.1:3000/cb/../evil") {
		t.Error("path-traversal URI accepted")
	}
	if cl.RedirectAllowed("http://127.0.0.1:3000/cb2") {
		t.Error("superstring URI accepted")
	}
}

func TestPersonaValidation(t *testing.T) {
	noPersonas := `
issuer = "http://127.0.0.1:9111"
seed = "s"
[[clients]]
client_id = "app"
client_secret = "x"
redirect_uris = ["http://127.0.0.1:3000/cb"]
`
	loadErr(t, noPersonas, "at least one [[personas]]")
	loadErr(t, minimalTOML+"\n[[personas]]\nname = \"alice\"\nsubject = \"user-2\"\n",
		`persona name "alice" is defined twice`)
	loadErr(t, minimalTOML+"\n[[personas]]\nname = \"bob\"\nsubject = \"user-1\"\n",
		`subject "user-1" is defined twice`)
	loadErr(t, strings.Replace(minimalTOML, `subject = "user-1"`, "", 1), "needs a subject")
}

func TestClaimValidation(t *testing.T) {
	// A persona must not be able to forge iss/exp/etc. through the claims
	// table — the whole tool is about tokens that do not lie.
	loadErr(t, minimalTOML+"\n[personas.claims]\niss = \"https://evil.example.test\"\n", `claim "iss" is reserved`)
	// Nested tables are rejected in 0.1.0 to keep snapshots eyeballable.
	loadErr(t, minimalTOML+"\n[personas.claims.address]\ncity = \"Tokyo\"\n", "unsupported claim type")
}

func TestTyposRejected(t *testing.T) {
	// Unknown keys fail loudly: a typo'd fixture must not silently mint
	// tokens missing the claim a test expects.
	loadErr(t, minimalTOML+"\nisuer = \"typo\"\n", `unknown key "isuer"`)
	loadErr(t, minimalTOML+"\nemial = \"typo@example.test\"\n", `unknown key "emial"`)
	loadErr(t, minimalTOML+"\nemail_verified = \"yes\"\n", "must be true or false")
}

func TestPublicClientHasEmptySecret(t *testing.T) {
	src := strings.Replace(minimalTOML, `client_secret = "secret"`+"\n", "", 1)
	cl, _ := load(t, src).Client("app")
	if cl.Secret != "" {
		t.Errorf("secret = %q, want empty (public client)", cl.Secret)
	}
}

func TestPersonaNamesPreserveFileOrder(t *testing.T) {
	src := minimalTOML + "\n[[personas]]\nname = \"bob\"\nsubject = \"user-2\"\n"
	if got := strings.Join(load(t, src).PersonaNames(), ","); got != "alice,bob" {
		t.Errorf("PersonaNames = %s", got)
	}
}

func TestLoadFileReportsPath(t *testing.T) {
	_, err := LoadFile("/nonexistent/personas.toml")
	if err == nil || !strings.Contains(err.Error(), "read config") {
		t.Fatalf("err = %v", err)
	}
}
