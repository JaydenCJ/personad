// Package cli implements the personad command line: serve, mint, decode,
// personas, jwks, discovery, validate, version. It is exercised in-process
// by the test suite, so Run takes explicit writers and returns an exit code
// instead of touching os globals.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JaydenCJ/personad/internal/config"
	"github.com/JaydenCJ/personad/internal/jose"
	"github.com/JaydenCJ/personad/internal/oidc"
	"github.com/JaydenCJ/personad/internal/version"
)

// Exit codes: 0 success, 1 operational failure, 2 usage error.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

const usage = `personad %s — deterministic fake OIDC provider for dev and CI

Usage:
  personad serve     --config personas.toml [--addr 127.0.0.1:9111]
  personad mint      --config personas.toml --persona NAME --client ID
                     [--kind id|access] [--scope "openid profile email groups"]
                     [--nonce N] [--at RFC3339]
  personad decode    --config personas.toml TOKEN
  personad personas  --config personas.toml
  personad jwks      --config personas.toml
  personad discovery --config personas.toml
  personad validate  --config personas.toml
  personad version

Run 'personad <command> -h' for command flags.
`

// Run dispatches argv (without the program name) and returns an exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version.Version)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(rest, stdout, stderr)
	case "mint":
		return cmdMint(rest, stdout, stderr)
	case "decode":
		return cmdDecode(rest, stdout, stderr)
	case "personas":
		return cmdPersonas(rest, stdout, stderr)
	case "jwks":
		return cmdJWKS(rest, stdout, stderr)
	case "discovery":
		return cmdDiscovery(rest, stdout, stderr)
	case "validate":
		return cmdValidate(rest, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "personad %s\n", version.Version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprintf(stdout, usage, version.Version)
		return exitOK
	default:
		fmt.Fprintf(stderr, "personad: unknown command %q\n\n", cmd)
		fmt.Fprintf(stderr, usage, version.Version)
		return exitUsage
	}
}

// newFlags builds a FlagSet that reports usage errors on stderr and never
// calls os.Exit.
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags runs fs over args. ok is true when the command should proceed;
// otherwise code is the exit code — 0 for an explicit -h/--help request
// (asking for help is not an error), 2 for a genuine usage mistake.
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	switch err := fs.Parse(args); err {
	case nil:
		return exitOK, true
	case flag.ErrHelp:
		return exitOK, false
	default:
		return exitUsage, false
	}
}

// loadIssuer loads + validates the config and constructs the signer. RSA
// key paths are resolved relative to the config file so persona fixtures
// stay relocatable.
func loadIssuer(path string, stderr io.Writer) (*oidc.Issuer, int) {
	if path == "" {
		fmt.Fprintln(stderr, "personad: --config is required")
		return nil, exitUsage
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "personad: %v\n", err)
		return nil, exitFail
	}
	var signer jose.Signer
	switch cfg.Algorithm {
	case "RS256":
		keyPath := cfg.RSAKeyFile
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(filepath.Dir(path), keyPath)
		}
		pemBytes, err := os.ReadFile(keyPath)
		if err != nil {
			fmt.Fprintf(stderr, "personad: read rsa_key_file: %v\n", err)
			return nil, exitFail
		}
		signer, err = jose.LoadRSAPEM(pemBytes)
		if err != nil {
			fmt.Fprintf(stderr, "personad: %s: %v\n", keyPath, err)
			return nil, exitFail
		}
	default: // "EdDSA", enforced by validation
		signer = jose.NewEdSigner(cfg.Seed)
	}
	return oidc.NewIssuer(cfg, signer), exitOK
}

func cmdMint(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("mint", stderr)
	cfgPath := fs.String("config", "", "persona file (TOML)")
	persona := fs.String("persona", "", "persona handle to mint for")
	client := fs.String("client", "", "client_id for the aud claim")
	kind := fs.String("kind", "id", `token kind: "id" or "access"`)
	scope := fs.String("scope", "openid profile email groups", "space-separated scopes")
	nonce := fs.String("nonce", "", "nonce claim for the ID token")
	at := fs.String("at", "", "issue time (RFC 3339); overrides tokens.issued_at")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	iss, code := loadIssuer(*cfgPath, stderr)
	if code != exitOK {
		return code
	}
	p, ok := iss.Cfg.Persona(*persona)
	if !ok {
		fmt.Fprintf(stderr, "personad: unknown persona %q (have: %s)\n",
			*persona, strings.Join(iss.Cfg.PersonaNames(), ", "))
		return exitFail
	}
	if _, ok := iss.Cfg.Client(*client); !ok {
		fmt.Fprintf(stderr, "personad: unknown client %q; --client must name a [[clients]] entry\n", *client)
		return exitFail
	}
	issueAt := iss.IssueTime()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintf(stderr, "personad: --at %q is not an RFC 3339 timestamp\n", *at)
			return exitUsage
		}
		issueAt = t.UTC()
	}
	scopes := oidc.SplitScope(*scope)
	var token string
	var err error
	switch *kind {
	case "id":
		token, err = iss.IDToken(p, *client, *nonce, scopes, issueAt)
	case "access":
		token, err = iss.AccessToken(p, *client, scopes, issueAt)
	default:
		fmt.Fprintf(stderr, "personad: --kind must be \"id\" or \"access\", got %q\n", *kind)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintf(stderr, "personad: %v\n", err)
		return exitFail
	}
	fmt.Fprintln(stdout, token)
	return exitOK
}

func cmdDecode(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("decode", stderr)
	cfgPath := fs.String("config", "", "persona file (TOML) whose key verifies the signature")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "personad: decode takes exactly one TOKEN argument")
		return exitUsage
	}
	raw := fs.Arg(0)
	iss, code := loadIssuer(*cfgPath, stderr)
	if code != exitOK {
		return code
	}
	tok, err := jose.VerifyJWT(iss.Signer, raw)
	if err != nil {
		fmt.Fprintf(stderr, "personad: %v\n", err)
		return exitFail
	}
	out := jose.NewObj().
		Set("header", jose.NewObj().SetSorted(tok.Header)).
		Set("claims", jose.NewObj().SetSorted(tok.Claims)).
		Set("signature", "verified")
	_, _ = stdout.Write(out.EncodeIndent())
	return exitOK
}

func cmdPersonas(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("personas", stderr)
	cfgPath := fs.String("config", "", "persona file (TOML)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	iss, code := loadIssuer(*cfgPath, stderr)
	if code != exitOK {
		return code
	}
	fmt.Fprintf(stdout, "%-12s %-20s %-26s %s\n", "PERSONA", "SUBJECT", "EMAIL", "GROUPS")
	for _, p := range iss.Cfg.Personas {
		fmt.Fprintf(stdout, "%-12s %-20s %-26s %s\n",
			p.Name, p.Subject, p.Email, strings.Join(p.Groups, ","))
	}
	return exitOK
}

func cmdJWKS(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("jwks", stderr)
	cfgPath := fs.String("config", "", "persona file (TOML)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	iss, code := loadIssuer(*cfgPath, stderr)
	if code != exitOK {
		return code
	}
	_, _ = stdout.Write(iss.JWKS().EncodeIndent())
	return exitOK
}

func cmdDiscovery(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("discovery", stderr)
	cfgPath := fs.String("config", "", "persona file (TOML)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	iss, code := loadIssuer(*cfgPath, stderr)
	if code != exitOK {
		return code
	}
	_, _ = stdout.Write(iss.Discovery().EncodeIndent())
	return exitOK
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("validate", stderr)
	cfgPath := fs.String("config", "", "persona file (TOML)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	iss, code := loadIssuer(*cfgPath, stderr)
	if code != exitOK {
		return code
	}
	frozen := "live clock"
	if iss.Cfg.IssuedAt != nil {
		frozen = "frozen at " + iss.Cfg.IssuedAt.Format(time.RFC3339)
	}
	fmt.Fprintf(stdout, "ok: %d persona(s), %d client(s), alg %s, kid %s, iat %s\n",
		len(iss.Cfg.Personas), len(iss.Cfg.Clients), iss.Signer.Alg(), iss.Signer.KID(), frozen)
	return exitOK
}
