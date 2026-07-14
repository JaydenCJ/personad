# Persona file reference

A persona file is a TOML document that fully determines personad's behavior
— and, together with the frozen clock, fully determines every token byte.
This page lists every key. Unknown keys are rejected: a typo fails the load
instead of silently minting tokens without the claim you expected.

## Top level

| Key | Required | Effect |
|---|---|---|
| `issuer` | yes | Absolute `http(s)` URL, no trailing slash. Becomes the `iss` claim and the base of every discovery endpoint. |
| `seed` | yes | Arbitrary string. SHA-256-derived into the Ed25519 signing key; same seed → same key → same JWKS on every machine. |

## `[tokens]`

| Key | Default | Effect |
|---|---|---|
| `algorithm` | `"EdDSA"` | `"EdDSA"` (seed-derived Ed25519) or `"RS256"` (key from `rsa_key_file`). Both signature schemes are deterministic. |
| `rsa_key_file` | — | PKCS#1 or PKCS#8 PEM path, resolved relative to the persona file. Required with (and only valid with) RS256. |
| `ttl` | `"1h"` | Access/ID token lifetime (`exp = iat + ttl`). Go duration syntax: `"90m"`, `"24h"`. |
| `issued_at` | live clock | RFC 3339 timestamp (quoted string). Freezes `iat`/`exp`/`auth_time`, making token bytes immutable — the snapshot-testing switch. |

## `[[clients]]`

| Key | Required | Effect |
|---|---|---|
| `client_id` | yes | Unique client identifier. |
| `client_secret` | no | Omit it for a public client: no secret is accepted at `/token`, and PKCE becomes mandatory at `/authorize`. |
| `redirect_uris` | yes (≥1) | Exact-match allowlist. Absolute URLs, no fragments; no prefix or wildcard matching, by design. |

## `[[personas]]`

| Key | Required | Effect |
|---|---|---|
| `name` | yes | The handle used by `--persona`, the `?persona=` parameter and the picker page. Unique. |
| `subject` | yes | The `sub` claim. Unique across personas. |
| `email` | no | Released (with `email_verified`) under the `email` scope. |
| `email_verified` | `false` | Boolean companion to `email`. |
| `groups` | no | String array, released under the `groups` scope. |

### `[personas.claims]`

Arbitrary extra claims for the most recent `[[personas]]` entry, released
under the `profile` scope and emitted **sorted by key** so map order never
leaks into token bytes. Values may be strings, integers, floats, booleans,
or flat arrays of those. Two things are rejected:

- **Reserved claims** (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `jti`,
  `auth_time`, `azp`, `client_id`, `scope`, `token_use`) — the issuer
  computes these; personas cannot make tokens lie.
- **Nested tables** — legal JSON, but excluded from 0.1.0 to keep token
  snapshots easy to eyeball.

## Scope release rules

The same rules shape ID tokens, JWT access tokens and `/userinfo`:

| Requested scope | Claims released |
|---|---|
| `openid` | registered claims only (`iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`) |
| `email` | + `email`, `email_verified` |
| `groups` | + `groups` |
| `profile` | + every `[personas.claims]` entry, sorted by key |

Unknown scopes are accepted and echoed back but release nothing.

## The TOML subset

personad parses a deliberate subset of TOML: comments, bare/quoted/dotted
keys, basic and literal strings, integers, floats, booleans, (multi-line)
arrays, tables and arrays of tables. Multi-line strings, inline tables and
bare datetimes are rejected with an error that says what to write instead —
notably, `issued_at` must be a *quoted* RFC 3339 string.
