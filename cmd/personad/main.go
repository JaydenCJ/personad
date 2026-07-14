// Command personad is a deterministic fake OIDC provider for dev and CI.
package main

import (
	"os"

	"github.com/JaydenCJ/personad/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
