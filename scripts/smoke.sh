#!/usr/bin/env bash
# End-to-end smoke test for personad: builds the binary, mints byte-stable
# tokens against the example config, then boots a real server on loopback
# and drives the full authorization-code + PKCE flow with curl. No external
# network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/personad"
CFG="$ROOT/examples/personas.toml"

# The exact ID token examples/personas.toml + frozen clock must produce.
GOLDEN="eyJhbGciOiJFZERTQSIsImtpZCI6ImZnSkc3TzYzcDRHblZ2bFdEbGc3b3JSNzJTeGFYZWM0UFlZMjNSaEN5ZE0iLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkxMTEiLCJzdWIiOiJ1c2VyLWFsaWNlLTAwMSIsImF1ZCI6IndlYi1hcHAiLCJleHAiOjE3NjcyMjkyMDAsImlhdCI6MTc2NzIyNTYwMCwiYXV0aF90aW1lIjoxNzY3MjI1NjAwLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUudGVzdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJkZXYiXSwiZGVwYXJ0bWVudCI6ImVuZ2luZWVyaW5nIiwibGV2ZWwiOjV9.eS_CBeCGZ2JR0Mtk1gZ0y3MXuEK4w_M-48mo3X913Q_tbQZtlOCg3N44ZS514RKY60Ovr-NKnh4PpEkdrFlQCw"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/personad) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" version | grep -qx "personad 0.1.0" || fail "version mismatch"

echo "3. validate the example persona file"
"$BIN" validate --config "$CFG" | grep -q "2 persona(s), 2 client(s), alg EdDSA" \
  || fail "validate output wrong"

echo "4. minted tokens are byte-stable and match the golden snapshot"
T1="$("$BIN" mint --config "$CFG" --persona alice --client web-app)"
T2="$("$BIN" mint --config "$CFG" --persona alice --client web-app)"
[ "$T1" = "$T2" ] || fail "two mints differ"
[ "$T1" = "$GOLDEN" ] || fail "mint does not match the golden token"

echo "5. decode verifies the signature and shows claims"
"$BIN" decode --config "$CFG" "$T1" | grep -q '"department": "engineering"' \
  || fail "decode missing custom claim"
"$BIN" decode --config "$CFG" "$T1" | grep -q '"signature": "verified"' \
  || fail "decode did not verify"

echo "6. personas / jwks / discovery subcommands"
"$BIN" personas --config "$CFG" | grep -q "user-alice-001" || fail "personas table wrong"
"$BIN" jwks --config "$CFG" | grep -q '"kty": "OKP"' || fail "jwks wrong"
"$BIN" discovery --config "$CFG" | grep -q '"code_challenge_methods_supported"' \
  || fail "discovery wrong"

echo "7. boot the server on loopback"
PORT=9111
for CANDIDATE in 9111 9311 9511 9711; do
  if ! (exec 3<>"/dev/tcp/127.0.0.1/$CANDIDATE") 2>/dev/null; then
    PORT="$CANDIDATE"
    break
  fi
  exec 3>&- || true
done
"$BIN" serve --config "$CFG" --addr "127.0.0.1:$PORT" >"$WORKDIR/serve.log" 2>&1 &
SERVER_PID=$!
BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 50); do
  curl -sf "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "$BASE/healthz" | grep -q '"status": "ok"' || fail "server did not come up"

echo "8. discovery and JWKS over HTTP"
curl -sf "$BASE/.well-known/openid-configuration" | grep -q '"issuer": "http://127.0.0.1:9111"' \
  || fail "http discovery wrong"
curl -sf "$BASE/jwks.json" | grep -q '"alg": "EdDSA"' || fail "http jwks wrong"

echo "9. authorization-code + PKCE flow with curl"
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"   # RFC 7636 vector
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
LOCATION="$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$BASE/authorize?response_type=code&client_id=spa&redirect_uri=http://127.0.0.1:5173/callback&scope=openid%20profile%20email%20groups&state=st-1&nonce=n-1&persona=alice&code_challenge=$CHALLENGE&code_challenge_method=S256")"
echo "$LOCATION" | grep -q "state=st-1" || fail "state not echoed"
CODE="$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[ -n "$CODE" ] || fail "no authorization code in redirect"

curl -sf "$BASE/token" \
  -d grant_type=authorization_code -d "code=$CODE" \
  -d redirect_uri=http://127.0.0.1:5173/callback \
  -d client_id=spa -d "code_verifier=$VERIFIER" > "$WORKDIR/tokens.json" \
  || fail "token exchange failed"
grep -q '"token_type": "Bearer"' "$WORKDIR/tokens.json" || fail "no bearer token"
grep -q '"id_token"' "$WORKDIR/tokens.json" || fail "no id_token"

echo "10. userinfo returns the persona's claims"
ACCESS="$(sed -n 's/.*"access_token": "\([^"]*\)".*/\1/p' "$WORKDIR/tokens.json")"
curl -sf "$BASE/userinfo" -H "Authorization: Bearer $ACCESS" > "$WORKDIR/userinfo.json"
grep -q '"sub": "user-alice-001"' "$WORKDIR/userinfo.json" || fail "userinfo sub wrong"
grep -q '"department": "engineering"' "$WORKDIR/userinfo.json" || fail "userinfo custom claim missing"

echo "11. replayed codes are rejected"
REPLAY_STATUS="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/token" \
  -d grant_type=authorization_code -d "code=$CODE" \
  -d redirect_uri=http://127.0.0.1:5173/callback \
  -d client_id=spa -d "code_verifier=$VERIFIER")"
[ "$REPLAY_STATUS" = "400" ] || fail "code replay returned $REPLAY_STATUS, want 400"

echo "12. usage errors exit 2"
set +e
"$BIN" mint --config "$CFG" --persona alice --client web-app --kind refresh >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --kind should exit 2"
"$BIN" serve --config "$CFG" --addr 0.0.0.0:9111 >/dev/null 2>&1
[ $? -eq 2 ] || fail "non-loopback bind should exit 2"
set -e

echo "SMOKE OK"
