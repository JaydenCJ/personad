// The serve subcommand: binds the OIDC provider to loopback and runs until
// interrupted. Kept apart from cli.go because it is the only command with a
// long-running side effect.
package cli

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/JaydenCJ/personad/internal/oidc"
)

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("serve", stderr)
	cfgPath := fs.String("config", "", "persona file (TOML)")
	addr := fs.String("addr", "127.0.0.1:9111", "listen address (loopback by default)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	iss, code := loadIssuer(*cfgPath, stderr)
	if code != exitOK {
		return code
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		fmt.Fprintf(stderr, "personad: --addr %q must be host:port\n", *addr)
		return exitUsage
	}
	if !isLoopbackHost(host) {
		// A fake IdP that mints valid-looking identities must never be
		// reachable from off-machine by accident. Non-loopback binds are a
		// hard error, not a warning.
		fmt.Fprintf(stderr, "personad: refusing to bind non-loopback address %q; personad is a test double, keep it on 127.0.0.1\n", *addr)
		return exitUsage
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(stderr, "personad: listen: %v\n", err)
		return exitFail
	}
	srv := oidc.NewServer(iss)
	fmt.Fprintf(stdout, "personad %s listening\n", ln.Addr())
	fmt.Fprintf(stdout, "issuer:    %s\n", iss.Cfg.Issuer)
	fmt.Fprintf(stdout, "discovery: %s/.well-known/openid-configuration\n", iss.Cfg.Issuer)
	fmt.Fprintf(stdout, "personas:  %s\n", strings.Join(iss.Cfg.PersonaNames(), ", "))
	if err := http.Serve(ln, srv.Handler()); err != nil {
		fmt.Fprintf(stderr, "personad: serve: %v\n", err)
		return exitFail
	}
	return exitOK
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
