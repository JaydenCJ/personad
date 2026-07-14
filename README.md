# personad

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Go ≥1.22](https://img.shields.io/badge/go-%E2%89%A51.22-00ADD8)](go.mod) [![Version 0.1.0](https://img.shields.io/badge/version-0.1.0-informational)](CHANGELOG.md) ![Tests](https://img.shields.io/badge/tests-91%20passed-brightgreen) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**personad：an open-source deterministic fake OIDC provider for dev and CI — personas in TOML, byte-stable tokens for snapshot tests, full discovery/JWKS/PKCE. Built for assertions, not demos.**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/personad && cd personad
go build -o personad ./cmd/personad    # single static binary, stdlib only
```

> Pre-release: v0.1.0 is not tagged on a package registry yet; build from source as above (any Go ≥1.22).

## Why personad?

Every OAuth integration test eventually fights a real identity provider: rate limits, expiring test tenants, tokens whose `iat`/`jti` change on every run so nothing can be snapshot-asserted, and a login page in the middle of your headless CI job. The usual escape hatches all cost something — mock-oauth2-server is excellent but drags a JVM into every web project's CI image; Keycloak in dev mode is a 600 MB container that takes longer to boot than your test suite takes to run; hand-rolled JWT stubs skip discovery/JWKS/PKCE, so the exact code paths you meant to test (issuer validation, key rotation, verifier checks) stay untested. personad is a 6 MB static binary that speaks enough real OIDC for standard client libraries to complete the full code + PKCE flow against it — and it is deterministic end to end: the signing key derives from a seed in your config, the clock can be frozen, claim order is fixed, so the same persona file mints the same token bytes on every machine, forever. Your assertions can be `assertEquals`, not `assertMatches`.

| | personad | mock-oauth2-server | oauth2-mock-server (npm) | Keycloak dev mode |
|---|---|---|---|---|
| Runtime footprint | 6 MB static binary | JVM | Node.js | JVM container |
| Byte-stable tokens for snapshot tests | ✅ seed + frozen clock | ❌ random keys per boot | ❌ random keys per boot | ❌ |
| Personas as reviewable config | ✅ TOML in your repo | ⚠️ JSON/code callbacks | ⚠️ code | ⚠️ realm export JSON |
| Discovery + JWKS + PKCE (S256) | ✅ | ✅ | ✅ | ✅ |
| Mint a token with no server (CLI) | ✅ `personad mint` | ❌ | ❌ | ❌ |
| Refresh rotation, introspection, userinfo | ✅ | ✅ | ⚠️ partial | ✅ |
| Runtime dependencies | 0 (Go stdlib) | JVM + libs | 4 npm packages | hundreds |

<sub>Footprints checked 2026-07-13: personad's binary is ~6 MB stripped (`go build -ldflags "-s -w"`; ~9 MB unstripped); mock-oauth2-server needs a JRE (≈200 MB) or its ~180 MB Docker image; the Keycloak container is ≈430–600 MB depending on tag.</sub>

## Features

- **Personas in TOML** — users are data, not code: subjects, emails, groups and arbitrary custom claims live in a reviewable file next to your tests, validated so hard that a typo'd key fails the run instead of silently minting the wrong token.
- **Byte-stable tokens** — Ed25519 keys derived from a config seed, fixed claim ordering, frozen `issued_at`, derived `jti`s: the same file produces the same compact JWT on every machine. A golden token is pinned in personad's own test suite so drift is a breaking change.
- **The full front door** — `/.well-known/openid-configuration`, JWKS with RFC 7638 kids, authorization-code flow with an HTML persona picker, PKCE (S256 + plain, mandatory for public clients), refresh rotation, client_credentials, userinfo and RFC 7662 introspection.
- **Mint without a server** — `personad mint` writes an ID or access token straight to stdout for unit tests and fixtures; `personad decode` verifies and pretty-prints any token it issued.
- **Honest errors, real rejections** — replayed codes, mismatched redirect URIs, wrong verifiers, cross-client redemptions and id-tokens-sent-to-userinfo all fail exactly the way a conforming IdP would fail them, with messages that name the mistake.
- **Safe by construction** — refuses to bind anything but loopback, no telemetry, no network calls, zero dependencies; the only thing personad ever talks to is your test suite.

## Quickstart

```bash
go build -o personad ./cmd/personad
./personad mint --config examples/personas.toml --persona alice --client web-app
```

Real captured output — run it twice, diff it, it's the same bytes:

```text
eyJhbGciOiJFZERTQSIsImtpZCI6ImZnSkc3TzYzcDRHblZ2bFdEbGc3b3JSNzJTeGFYZWM0UFlZMjNSaEN5ZE0iLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkxMTEiLCJzdWIiOiJ1c2VyLWFsaWNlLTAwMSIsImF1ZCI6IndlYi1hcHAiLCJleHAiOjE3NjcyMjkyMDAsImlhdCI6MTc2NzIyNTYwMCwiYXV0aF90aW1lIjoxNzY3MjI1NjAwLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUudGVzdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJkZXYiXSwiZGVwYXJ0bWVudCI6ImVuZ2luZWVyaW5nIiwibGV2ZWwiOjV9.eS_CBeCGZ2JR0Mtk1gZ0y3MXuEK4w_M-48mo3X913Q_tbQZtlOCg3N44ZS514RKY60Ovr-NKnh4PpEkdrFlQCw
```

Then boot the real provider and point your app's OIDC client at it:

```bash
./personad serve --config examples/personas.toml
```

```text
personad 127.0.0.1:9111 listening
issuer:    http://127.0.0.1:9111
discovery: http://127.0.0.1:9111/.well-known/openid-configuration
personas:  alice, bob
```

Complete the code + PKCE flow (see `examples/code-flow.sh` for the curl version), then hit userinfo — real captured output:

```text
$ curl -s http://127.0.0.1:9111/userinfo -H "Authorization: Bearer $ACCESS"
{
  "sub": "user-alice-001",
  "email": "alice@example.test",
  "email_verified": true,
  "groups": [
    "admin",
    "dev"
  ],
  "department": "engineering",
  "level": 5
}
```

## Persona files

A persona file fully determines every token byte. The full reference lives in [docs/persona-format.md](docs/persona-format.md); the load-bearing keys:

| Key | Default | Effect |
|---|---|---|
| `issuer` | required | `iss` claim and base URL of all endpoints (no trailing slash) |
| `seed` | required | derives the Ed25519 signing key — same seed, same JWKS, everywhere |
| `tokens.issued_at` | live clock | quoted RFC 3339 timestamp; freezes `iat`/`exp` for snapshot-safe bytes |
| `tokens.ttl` | `"1h"` | token lifetime (`exp = iat + ttl`) |
| `tokens.algorithm` | `"EdDSA"` | or `"RS256"` with `tokens.rsa_key_file` for EdDSA-less client libraries |
| `[[clients]]` | required | `client_id`, optional `client_secret` (omit → public client, PKCE forced), exact-match `redirect_uris` |
| `[[personas]]` | required | `name`, `subject`, `email`, `groups`, plus free-form `[personas.claims]` |

Scopes gate claim release the same way everywhere (ID token, access token, userinfo): `email` → email claims, `groups` → groups, `profile` → all custom claims, sorted by key.

## CLI reference

| Command | Effect |
|---|---|
| `serve --config F [--addr 127.0.0.1:9111]` | run the provider (loopback only, enforced) |
| `mint --config F --persona P --client C` | print a token; `--kind id\|access`, `--scope`, `--nonce`, `--at RFC3339` |
| `decode --config F TOKEN` | verify signature, pretty-print header + claims |
| `personas --config F` | table of configured personas |
| `jwks` / `discovery --config F` | print the JWKS / discovery document without serving |
| `validate --config F` | check a persona file; exit 1 with the offending key on failure |

Exit codes: `0` success, `1` operational failure, `2` usage error.

## Verification

This repository ships no CI; every claim above is verified by local runs:

```bash
go test ./...            # 91 deterministic tests, no external network, < 5 s
bash scripts/smoke.sh    # builds, checks the golden token, drives the full
                         # code+PKCE flow with curl — prints SMOKE OK
```

## Architecture

```mermaid
flowchart LR
    F[personas.toml] --> P[toml: subset parser]
    P --> C[config: validate]
    C --> I[issuer: deterministic claims]
    K[seed / PEM] --> J[jose: keys, ordered JSON, JWT]
    J --> I
    I --> M[CLI mint / decode]
    I --> S[oidc server]
    S --> D["discovery + JWKS"]
    S --> A["authorize + PKCE"]
    S --> T["token / refresh / introspect"]
    S --> U[userinfo]
    A --> ST[(grant store)]
    ST --> T
```

## Roadmap

- [x] v0.1.0 — TOML personas, seed-derived keys, frozen clock, code+PKCE flow, refresh rotation, client_credentials, userinfo, introspection, mint/decode CLI, 91 tests + smoke script
- [ ] Device-code and implicit-grant emulation for legacy client testing
- [ ] Fault injection: `--chaos` flags for expired tokens, skewed clocks and wrong-kid JWKS to test client error paths
- [ ] Multiple concurrent issuers in one process for multi-tenant apps
- [ ] Opt-in request log (`--log jsonl`) for asserting on the exact requests a client library sends
- [ ] `personad export-jwks` for pre-provisioning resource servers

See the [open issues](https://github.com/JaydenCJ/personad/issues) for the full list.

## Contributing

Issues, discussions and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the local workflow (format, vet, tests, `SMOKE OK`) and the determinism ground rules. Good entry points are labelled [good first issue](https://github.com/JaydenCJ/personad/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22), and design questions live in [Discussions](https://github.com/JaydenCJ/personad/discussions).

## License

[MIT](LICENSE)
