#!/usr/bin/env bash
# Drives the full authorization-code + PKCE flow against a locally running
# personad with nothing but curl — the same requests your app's OIDC client
# library sends. Start the provider first:
#
#   personad serve --config examples/personas.toml
#
# Then: bash examples/code-flow.sh
set -euo pipefail

ISSUER="${ISSUER:-http://127.0.0.1:9111}"
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" # RFC 7636 test vector
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
TOKENS="$(mktemp)"
trap 'rm -f "$TOKENS"' EXIT

echo "==> discovery"
curl -sf "$ISSUER/.well-known/openid-configuration" | head -6

echo "==> authorize (public client, PKCE S256) — grab the code from the redirect"
LOCATION=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$ISSUER/authorize?response_type=code&client_id=spa&redirect_uri=http://127.0.0.1:5173/callback&scope=openid%20profile%20email%20groups&state=st-1&nonce=n-1&persona=alice&code_challenge=$CHALLENGE&code_challenge_method=S256")
CODE=$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
echo "code = $CODE"

echo "==> token exchange (code_verifier proves possession)"
curl -sf "$ISSUER/token" \
  -d grant_type=authorization_code \
  -d "code=$CODE" \
  -d redirect_uri=http://127.0.0.1:5173/callback \
  -d client_id=spa \
  -d "code_verifier=$VERIFIER" | tee "$TOKENS" | head -8

echo "==> userinfo with the access token"
ACCESS=$(sed -n 's/.*"access_token": "\([^"]*\)".*/\1/p' "$TOKENS")
curl -sf "$ISSUER/userinfo" -H "Authorization: Bearer $ACCESS"
