// In-process CLI tests: Run() with captured writers, asserting on real
// stdout/stderr text and exit codes — the same surface scripts/smoke.sh
// checks end-to-end.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JaydenCJ/personad/internal/version"
)

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

// run executes the CLI in-process and returns (exitCode, stdout, stderr).
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := Run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// writeConfig drops the standard test config into a temp dir.
func writeConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "personas.toml")
	if err := os.WriteFile(path, []byte(testTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersionAndHelp(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != 0 || strings.TrimSpace(out) != "personad "+version.Version {
		t.Fatalf("version: exit=%d out=%q", code, out)
	}
	code, out, _ = run(t, "--help")
	if code != 0 || !strings.Contains(out, "personad serve") {
		t.Fatalf("help: exit=%d out=%q", code, out)
	}
	// Per-command -h prints the flag reference and is not an error.
	code, _, errOut := run(t, "mint", "-h")
	if code != 0 || !strings.Contains(errOut, "-persona") {
		t.Fatalf("mint -h: exit=%d stderr=%q", code, errOut)
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	code, _, errOut := run(t)
	if code != 2 || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("no args: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "frobnicate")
	if code != 2 || !strings.Contains(errOut, `unknown command "frobnicate"`) {
		t.Fatalf("unknown command: exit=%d stderr=%q", code, errOut)
	}
}

func TestValidateHappyPath(t *testing.T) {
	code, out, _ := run(t, "validate", "--config", writeConfig(t))
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "2 persona(s), 1 client(s), alg EdDSA") {
		t.Fatalf("out = %q", out)
	}
	if !strings.Contains(out, "frozen at 2026-01-01T00:00:00Z") {
		t.Fatalf("out = %q", out)
	}
}

func TestValidateFailures(t *testing.T) {
	// Broken config: exit 1 and the message names the file and the problem.
	path := filepath.Join(t.TempDir(), "broken.toml")
	if err := os.WriteFile(path, []byte("issuer = \"http://127.0.0.1:9111\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "validate", "--config", path)
	if code != 1 || !strings.Contains(errOut, "broken.toml") || !strings.Contains(errOut, "seed is required") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	// Missing --config entirely is a usage error.
	code, _, errOut = run(t, "validate")
	if code != 2 || !strings.Contains(errOut, "--config is required") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}

func TestMintIDTokenIsByteStable(t *testing.T) {
	cfg := writeConfig(t)
	_, out1, _ := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app")
	code, out2, _ := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if out1 != out2 {
		t.Fatalf("mint output differs:\n%s%s", out1, out2)
	}
	if !strings.HasPrefix(out1, "eyJ") || strings.Count(out1, ".") != 2 {
		t.Fatalf("not a compact JWT: %q", out1)
	}
}

func TestMintAccessTokenKindRoundTripsThroughDecode(t *testing.T) {
	cfg := writeConfig(t)
	code, out, _ := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app", "--kind", "access")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	// Round-trip through decode to prove it verifies and is an access token.
	code, decoded, errOut := run(t, "decode", "--config", cfg, strings.TrimSpace(out))
	if code != 0 {
		t.Fatalf("decode exit = %d, stderr %q", code, errOut)
	}
	if !strings.Contains(decoded, `"token_use": "access"`) {
		t.Fatalf("decoded = %s", decoded)
	}
	if !strings.Contains(decoded, `"signature": "verified"`) {
		t.Fatalf("decoded = %s", decoded)
	}
}

func TestMintUnknownPersonaOrClient(t *testing.T) {
	cfg := writeConfig(t)
	code, _, errOut := run(t, "mint", "--config", cfg, "--persona", "mallory", "--client", "web-app")
	if code != 1 || !strings.Contains(errOut, "alice, bob") {
		t.Fatalf("unknown persona should list available: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "ghost")
	if code != 1 || !strings.Contains(errOut, `unknown client "ghost"`) {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}

func TestMintFlagValidation(t *testing.T) {
	cfg := writeConfig(t)
	code, _, errOut := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app", "--kind", "refresh")
	if code != 2 || !strings.Contains(errOut, "--kind") {
		t.Fatalf("bad kind: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app", "--at", "noon")
	if code != 2 || !strings.Contains(errOut, "RFC 3339") {
		t.Fatalf("bad at: exit=%d stderr=%q", code, errOut)
	}
}

func TestMintAtOverridesFrozenTime(t *testing.T) {
	cfg := writeConfig(t)
	_, def, _ := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app")
	code, at, _ := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app",
		"--at", "2027-06-15T12:00:00Z")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if def == at {
		t.Fatal("--at did not change the token")
	}
	// And --at itself is deterministic.
	_, at2, _ := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app",
		"--at", "2027-06-15T12:00:00Z")
	if at != at2 {
		t.Fatal("--at mint not byte-stable")
	}
}

func TestMintScopeControlsClaims(t *testing.T) {
	cfg := writeConfig(t)
	_, tok, _ := run(t, "mint", "--config", cfg, "--persona", "alice", "--client", "web-app", "--scope", "openid")
	_, decoded, _ := run(t, "decode", "--config", cfg, strings.TrimSpace(tok))
	if strings.Contains(decoded, "email") {
		t.Fatalf("email released without email scope: %s", decoded)
	}
}

func TestDecodeErrors(t *testing.T) {
	cfg := writeConfig(t)
	// Same document, different seed → different key → must not verify.
	otherCfg := filepath.Join(t.TempDir(), "other.toml")
	if err := os.WriteFile(otherCfg, []byte(strings.Replace(testTOML, "ci-seed-1", "other-seed", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, tok, _ := run(t, "mint", "--config", otherCfg, "--persona", "alice", "--client", "web-app")
	code, _, errOut := run(t, "decode", "--config", cfg, strings.TrimSpace(tok))
	if code != 1 || !strings.Contains(errOut, "kid") {
		t.Fatalf("foreign token: exit=%d stderr=%q", code, errOut)
	}
	// Arg count is a usage error.
	code, _, errOut = run(t, "decode", "--config", cfg)
	if code != 2 || !strings.Contains(errOut, "exactly one TOKEN") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}

func TestPersonasTable(t *testing.T) {
	code, out, _ := run(t, "personas", "--config", writeConfig(t))
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"PERSONA", "alice", "user-alice-001", "admin,dev", "bob"} {
		if !strings.Contains(out, want) {
			t.Errorf("personas output missing %q:\n%s", want, out)
		}
	}
}

func TestJWKSCommandOutputsKey(t *testing.T) {
	code, out, _ := run(t, "jwks", "--config", writeConfig(t))
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{`"kty": "OKP"`, `"alg": "EdDSA"`, `"use": "sig"`} {
		if !strings.Contains(out, want) {
			t.Errorf("jwks missing %s:\n%s", want, out)
		}
	}
}

func TestDiscoveryCommandOutputsMetadata(t *testing.T) {
	code, out, _ := run(t, "discovery", "--config", writeConfig(t))
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"issuer": "http://127.0.0.1:9111"`) ||
		!strings.Contains(out, `"code_challenge_methods_supported"`) {
		t.Fatalf("discovery output wrong:\n%s", out)
	}
}

func TestServeAddrValidation(t *testing.T) {
	cfg := writeConfig(t)
	// A fake IdP must never accidentally listen on all interfaces.
	code, _, errOut := run(t, "serve", "--config", cfg, "--addr", "0.0.0.0:9111")
	if code != 2 || !strings.Contains(errOut, "refusing to bind non-loopback") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "serve", "--config", cfg, "--addr", "9111")
	if code != 2 || !strings.Contains(errOut, "host:port") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}

func TestRSAConfig(t *testing.T) {
	dir := t.TempDir()
	// Reuse the checked-in test key from the jose package.
	pemBytes, err := os.ReadFile("../jose/testdata/rsa_test_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	src := strings.Replace(testTOML, "[tokens]",
		"[tokens]\nalgorithm = \"RS256\"\nrsa_key_file = \"key.pem\"", 1)
	cfgPath := filepath.Join(dir, "personas.toml")
	if err := os.WriteFile(cfgPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// The key path must resolve against the config file, not the CWD.
	code, out, errOut := run(t, "validate", "--config", cfgPath)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "alg RS256") {
		t.Fatalf("out = %q", out)
	}
	_, tok1, _ := run(t, "mint", "--config", cfgPath, "--persona", "alice", "--client", "web-app")
	_, tok2, _ := run(t, "mint", "--config", cfgPath, "--persona", "alice", "--client", "web-app")
	if tok1 != tok2 {
		t.Fatal("RS256 mint not byte-stable")
	}
	// A missing key file is an operational error naming the key.
	bad := strings.Replace(src, "key.pem", "missing.pem", 1)
	badPath := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(badPath, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "validate", "--config", badPath)
	if code != 1 || !strings.Contains(errOut, "rsa_key_file") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}
