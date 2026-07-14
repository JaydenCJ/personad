# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Persona files in a strict TOML subset: issuer, seed, token settings,
  confidential/public clients, personas with email, groups and arbitrary
  custom claims — with typo-proof validation (unknown keys, reserved
  claims, duplicate subjects and malformed redirect URIs all fail loudly).
- Deterministic token minting: Ed25519 keys derived from the config seed,
  fixed claim ordering, an optional frozen `issued_at` clock and derived
  `jti`s, so the same persona file always produces byte-identical JWTs —
  safe to pin in snapshot tests (a golden token is itself under test).
- Full OIDC provider over loopback HTTP: discovery, JWKS,
  `/authorize` (code flow with an HTML persona picker), `/token`
  (authorization_code, refresh_token with rotation, client_credentials),
  `/userinfo`, RFC 7662 `/introspect` and `/healthz`.
- PKCE per RFC 7636: S256 and plain, verifier grammar enforcement,
  constant-time comparison, mandatory for public clients.
- Scope-based claim release shared by ID tokens, access tokens and
  userinfo: `email`, `groups`, and `profile` for custom claims.
- RS256 support via a PEM key file for client libraries without EdDSA,
  with RFC 7638 thumbprint `kid`s for both algorithms.
- CLI: `serve`, `mint`, `decode` (verify + pretty-print), `personas`,
  `jwks`, `discovery`, `validate`, `version`; exit codes 0/1/2; refuses
  non-loopback binds.
- Runnable examples (`examples/personas.toml`, `examples/code-flow.sh`)
  and a persona-file reference (`docs/persona-format.md`).
- 91 deterministic offline tests (unit + in-process HTTP + CLI) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/personad/releases/tag/v0.1.0
