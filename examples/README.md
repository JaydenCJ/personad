# personad examples

- **`personas.toml`** — the canonical example persona file: a frozen clock,
  one confidential client, one public (PKCE) client, and two personas with
  groups and custom claims. Every token shown in the main README is minted
  from this exact file, so you can reproduce them byte for byte:

  ```bash
  personad mint --config examples/personas.toml --persona alice --client web-app
  ```

- **`code-flow.sh`** — the full authorization-code + PKCE flow driven by
  plain curl against a running `personad serve`, ending with a `/userinfo`
  call. Useful as a crib sheet for what your OIDC client library does under
  the hood, and for eyeballing the JSON your app will receive:

  ```bash
  personad serve --config examples/personas.toml &
  bash examples/code-flow.sh
  ```

Both examples stay entirely on loopback and need no accounts, no browser
and no network.
