# Contributing to personad

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else (the smoke script also uses `curl`, which
every CI image already has).

```bash
git clone https://github.com/JaydenCJ/personad && cd personad
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, checks minted tokens against a golden
snapshot, then boots a real server on loopback and drives the full
authorization-code + PKCE flow with curl; it must finish by printing
`SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (91 deterministic tests, no external network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (token shaping lives in `internal/oidc.Issuer`, never in HTTP
   handlers).

## Ground rules

- Keep dependencies at zero — personad is standard library only, and that
  is a headline feature. Adding one needs strong justification in the PR.
- Determinism is the contract: anything that changes token bytes for an
  existing config (claim order, key derivation, kid computation) is a
  breaking change and needs a major-version discussion first. The golden
  token test exists to make such drift impossible to miss.
- No network calls, ever, beyond serving loopback HTTP. No telemetry.
- personad is a test double: never weaken the loopback-only bind, and keep
  error messages honest about what a real IdP would have rejected.
- Code comments and doc comments are written in English.

## Reporting bugs

Include the output of `personad version`, your persona file (redact
anything sensitive — seeds in bug reports should be throwaways), the exact
command or HTTP request, and what a conforming OIDC provider should have
returned instead. For token-shape issues, paste `personad decode` output.

## Security

personad mints intentionally forgeable identities for tests; never expose
it beyond loopback or reuse its seeds in production systems. For
vulnerabilities in personad itself, please do not open public issues — use
GitHub's private vulnerability reporting on this repository instead.
