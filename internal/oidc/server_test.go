// HTTP integration tests: the full authorization-code + PKCE dance against
// an in-process httptest server, plus every rejection a misbehaving client
// should hit. All traffic stays on loopback via httptest.
package oidc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JaydenCJ/personad/internal/config"
	"github.com/JaydenCJ/personad/internal/jose"
)

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg, err := config.Load(testTOML)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(NewIssuer(cfg, jose.NewEdSigner(cfg.Seed)))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

// noRedirect returns a client that surfaces 302s instead of following them
// (the redirect targets are fake app callback URLs that do not exist).
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, decodeBody(t, resp.Body)
}

func decodeBody(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	return m
}

// authorize drives GET /authorize and returns the redirect Location query.
func authorize(t *testing.T, ts *httptest.Server, params url.Values) url.Values {
	t.Helper()
	resp, err := noRedirect().Get(ts.URL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d, body %s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query()
}

func baseAuthParams() url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {"web-app"},
		"redirect_uri":  {"http://127.0.0.1:3000/callback"},
		"scope":         {"openid profile email groups"},
		"state":         {"st-1"},
		"nonce":         {"n-1"},
		"persona":       {"alice"},
	}
}

func postToken(t *testing.T, ts *httptest.Server, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, decodeBody(t, resp.Body)
}

// redeem drives a fresh authorize + token exchange for the confidential
// client and returns the token response body.
func redeem(t *testing.T, ts *httptest.Server) map[string]any {
	t.Helper()
	code := authorize(t, ts, baseAuthParams()).Get("code")
	status, body := postToken(t, ts, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:3000/callback"},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	})
	if status != 200 {
		t.Fatalf("token status = %d, body %v", status, body)
	}
	return body
}

// --- metadata ---------------------------------------------------------------

func TestMetadataEndpoints(t *testing.T) {
	s, ts := testServer(t)
	status, doc := getJSON(t, ts.URL+"/.well-known/openid-configuration")
	if status != 200 || doc["issuer"] != "http://127.0.0.1:9111" {
		t.Fatalf("discovery: status=%d issuer=%v", status, doc["issuer"])
	}
	if doc["jwks_uri"] != "http://127.0.0.1:9111/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
	status, doc = getJSON(t, ts.URL+"/jwks.json")
	keys := doc["keys"].([]any)
	if status != 200 || len(keys) != 1 {
		t.Fatalf("jwks: status=%d keys=%v", status, keys)
	}
	if kid := keys[0].(map[string]any)["kid"].(string); kid != s.Issuer.Signer.KID() {
		t.Errorf("kid = %s", kid)
	}
	status, doc = getJSON(t, ts.URL+"/healthz")
	if status != 200 || doc["status"] != "ok" {
		t.Fatalf("healthz: status=%d doc=%v", status, doc)
	}
}

// --- /authorize --------------------------------------------------------------

func TestAuthorizeIssuesCodeAndEchoesState(t *testing.T) {
	_, ts := testServer(t)
	q := authorize(t, ts, baseAuthParams())
	if q.Get("code") == "" {
		t.Fatal("no code in redirect")
	}
	if q.Get("state") != "st-1" {
		t.Errorf("state = %q", q.Get("state"))
	}
	if q.Get("error") != "" {
		t.Errorf("unexpected error %q", q.Get("error"))
	}
}

func TestAuthorizationCodesAreDeterministicAndSingleUse(t *testing.T) {
	// Two fresh servers hand out the same first code: assertable fixtures.
	_, ts1 := testServer(t)
	_, ts2 := testServer(t)
	c1 := authorize(t, ts1, baseAuthParams()).Get("code")
	c2 := authorize(t, ts2, baseAuthParams()).Get("code")
	if c1 != c2 {
		t.Fatalf("first codes differ: %s vs %s", c1, c2)
	}
	if !strings.HasPrefix(c1, "pc_") {
		t.Fatalf("code = %q", c1)
	}
	// Store-level guarantees: single use, seed-bound.
	st := NewStore("seed")
	code := st.NewCode(Grant{Persona: "alice"})
	if _, ok := st.TakeCode(code); !ok {
		t.Fatal("fresh code not redeemable")
	}
	if _, ok := st.TakeCode(code); ok {
		t.Fatal("code redeemable twice")
	}
	if NewStore("seed-a").NewCode(Grant{}) == NewStore("seed-b").NewCode(Grant{}) {
		t.Fatal("different seeds produced the same code")
	}
}

func TestAuthorizeInvalidClientNeverRedirects(t *testing.T) {
	// Redirecting an unknown client's error would be an open redirect.
	_, ts := testServer(t)
	for name, mutate := range map[string]func(url.Values){
		"unknown client":        func(p url.Values) { p.Set("client_id", "evil") },
		"unregistered redirect": func(p url.Values) { p.Set("redirect_uri", "http://evil.example.test/cb") },
		"superstring redirect":  func(p url.Values) { p.Set("redirect_uri", "http://127.0.0.1:3000/callback2") },
	} {
		p := baseAuthParams()
		mutate(p)
		resp, err := noRedirect().Get(ts.URL + "/authorize?" + p.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%s: status = %d, want 400", name, resp.StatusCode)
		}
	}
}

func TestAuthorizeErrorRedirects(t *testing.T) {
	_, ts := testServer(t)
	cases := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{"implicit flow", func(p url.Values) { p.Set("response_type", "token") }, "unsupported_response_type"},
		{"missing openid scope", func(p url.Values) { p.Set("scope", "email") }, "invalid_scope"},
		{"unknown persona", func(p url.Values) { p.Set("persona", "mallory") }, "access_denied"},
		{"unknown challenge method", func(p url.Values) {
			p.Set("code_challenge", "x")
			p.Set("code_challenge_method", "S512")
		}, "invalid_request"},
	}
	for _, c := range cases {
		p := baseAuthParams()
		c.mutate(p)
		q := authorize(t, ts, p)
		if q.Get("error") != c.wantError {
			t.Errorf("%s: error = %q, want %q (%s)", c.name, q.Get("error"), c.wantError, q.Get("error_description"))
		}
		if q.Get("state") != "st-1" {
			t.Errorf("%s: state not echoed on error redirect", c.name)
		}
	}
}

func TestAuthorizePublicClientRequiresPKCE(t *testing.T) {
	_, ts := testServer(t)
	p := baseAuthParams()
	p.Set("client_id", "spa")
	p.Set("redirect_uri", "http://127.0.0.1:5173/callback")
	q := authorize(t, ts, p)
	if q.Get("error") != "invalid_request" || !strings.Contains(q.Get("error_description"), "PKCE") {
		t.Fatalf("error = %q (%q)", q.Get("error"), q.Get("error_description"))
	}
}

func TestAuthorizeWithoutPersonaRendersPicker(t *testing.T) {
	_, ts := testServer(t)
	p := baseAuthParams()
	p.Del("persona")
	resp, err := http.Get(ts.URL + "/authorize?" + p.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "alice") || !strings.Contains(string(body), "bob") {
		t.Fatalf("picker missing personas: status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "persona=alice") {
		t.Fatal("picker links do not carry the persona parameter")
	}
}

// --- /token: authorization_code ------------------------------------------------

func TestFullCodeFlowConfidentialClient(t *testing.T) {
	s, ts := testServer(t)
	code := authorize(t, ts, baseAuthParams()).Get("code")
	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:3000/callback"},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}
	body := decodeBody(t, resp.Body)
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}
	if n, _ := body["expires_in"].(json.Number).Int64(); n != 3600 {
		t.Errorf("expires_in = %v", body["expires_in"])
	}
	idTok, err := jose.VerifyJWT(s.Issuer.Signer, body["id_token"].(string))
	if err != nil {
		t.Fatalf("id_token invalid: %v", err)
	}
	if idTok.StringClaim("nonce") != "n-1" {
		t.Errorf("nonce = %q", idTok.StringClaim("nonce"))
	}
	if idTok.StringClaim("sub") != "user-alice-001" {
		t.Errorf("sub = %q", idTok.StringClaim("sub"))
	}
	if _, err := jose.VerifyJWT(s.Issuer.Signer, body["access_token"].(string)); err != nil {
		t.Fatalf("access_token invalid: %v", err)
	}
}

func TestFullCodeFlowPublicClientWithPKCES256(t *testing.T) {
	_, ts := testServer(t)
	p := baseAuthParams()
	p.Set("client_id", "spa")
	p.Set("redirect_uri", "http://127.0.0.1:5173/callback")
	p.Set("code_challenge", S256Challenge(rfcVerifier))
	p.Set("code_challenge_method", "S256")
	code := authorize(t, ts, p).Get("code")
	if code == "" {
		t.Fatal("no code")
	}
	status, body := postToken(t, ts, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:5173/callback"},
		"client_id":     {"spa"},
		"code_verifier": {rfcVerifier},
	})
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	if body["id_token"] == nil {
		t.Fatal("no id_token")
	}
}

func TestTokenRejectsWrongVerifier(t *testing.T) {
	_, ts := testServer(t)
	p := baseAuthParams()
	p.Set("client_id", "spa")
	p.Set("redirect_uri", "http://127.0.0.1:5173/callback")
	p.Set("code_challenge", S256Challenge(rfcVerifier))
	p.Set("code_challenge_method", "S256")
	code := authorize(t, ts, p).Get("code")
	status, body := postToken(t, ts, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:5173/callback"},
		"client_id":     {"spa"},
		"code_verifier": {strings.Repeat("y", 43)},
	})
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("status=%d body=%v", status, body)
	}
}

func TestTokenCodeIsSingleUse(t *testing.T) {
	_, ts := testServer(t)
	code := authorize(t, ts, baseAuthParams()).Get("code")
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:3000/callback"},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	}
	if status, _ := postToken(t, ts, form); status != 200 {
		t.Fatalf("first redemption failed: %d", status)
	}
	status, body := postToken(t, ts, form)
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replayed code accepted: status=%d body=%v", status, body)
	}
}

func TestTokenRejectsGrantMismatches(t *testing.T) {
	_, ts := testServer(t)
	// redirect_uri differs from the authorization request:
	code := authorize(t, ts, baseAuthParams()).Get("code")
	status, body := postToken(t, ts, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:3000/other"},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	})
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("redirect mismatch: status=%d body=%v", status, body)
	}
	// Code issued to web-app redeemed by spa:
	code = authorize(t, ts, baseAuthParams()).Get("code")
	status, body = postToken(t, ts, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:3000/callback"},
		"client_id":     {"spa"},
		"code_verifier": {rfcVerifier},
	})
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("cross-client redemption: status=%d body=%v", status, body)
	}
}

func TestTokenClientAuthAndGrantTypeErrors(t *testing.T) {
	_, ts := testServer(t)
	code := authorize(t, ts, baseAuthParams()).Get("code")
	status, body := postToken(t, ts, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:3000/callback"},
		"client_id":     {"web-app"},
		"client_secret": {"wrong"},
	})
	if status != 401 || body["error"] != "invalid_client" {
		t.Fatalf("bad secret: status=%d body=%v", status, body)
	}
	status, body = postToken(t, ts, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	})
	if status != 400 || body["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant: status=%d body=%v", status, body)
	}
}

func TestTokenBasicAuthWorks(t *testing.T) {
	_, ts := testServer(t)
	code := authorize(t, ts, baseAuthParams()).Get("code")
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://127.0.0.1:3000/callback"},
	}
	req, _ := http.NewRequest("POST", ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("web-app", "s3cret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
}

// --- /token: refresh + client_credentials ----------------------------------------

func TestRefreshTokenRotates(t *testing.T) {
	_, ts := testServer(t)
	rt := redeem(t, ts)["refresh_token"].(string)
	if !strings.HasPrefix(rt, "pr_") {
		t.Fatalf("refresh_token = %q", rt)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	}
	status, body := postToken(t, ts, form)
	if status != 200 {
		t.Fatalf("refresh failed: %d %v", status, body)
	}
	if body["refresh_token"] == rt {
		t.Fatal("refresh token was not rotated")
	}
	// The old token is burned.
	if status, _ := postToken(t, ts, form); status != 400 {
		t.Fatalf("old refresh token still works: %d", status)
	}
}

func TestClientCredentialsGrant(t *testing.T) {
	s, ts := testServer(t)
	status, body := postToken(t, ts, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
		"scope":         {"api"},
	})
	if status != 200 {
		t.Fatalf("status = %d body %v", status, body)
	}
	tok, err := jose.VerifyJWT(s.Issuer.Signer, body["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if tok.StringClaim("sub") != "web-app" {
		t.Errorf("sub = %q", tok.StringClaim("sub"))
	}
	if _, ok := body["id_token"]; ok {
		t.Error("client_credentials must not return an id_token")
	}
	// Public clients have no secret to prove: rejected.
	status, body = postToken(t, ts, url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"spa"},
	})
	if status != 400 || body["error"] != "invalid_grant" {
		t.Errorf("public client: status=%d body=%v", status, body)
	}
}

// --- /userinfo -------------------------------------------------------------------

func mintAccessToken(t *testing.T, s *Server, scopes []string) string {
	t.Helper()
	p, _ := s.Issuer.Cfg.Persona("alice")
	tok, err := s.Issuer.AccessToken(p, "web-app", scopes, s.Issuer.IssueTime())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func getUserinfo(t *testing.T, ts *httptest.Server, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, decodeBody(t, resp.Body)
}

func TestUserinfoReturnsScopedClaims(t *testing.T) {
	s, ts := testServer(t)
	status, body := getUserinfo(t, ts, mintAccessToken(t, s, []string{"openid", "email", "groups", "profile"}))
	if status != 200 {
		t.Fatalf("status = %d body %v", status, body)
	}
	if body["sub"] != "user-alice-001" || body["email"] != "alice@example.test" {
		t.Errorf("body = %v", body)
	}
	if body["department"] != "engineering" {
		t.Errorf("custom claim missing: %v", body)
	}
}

func TestUserinfoHonorsScopeFromToken(t *testing.T) {
	s, ts := testServer(t)
	_, body := getUserinfo(t, ts, mintAccessToken(t, s, []string{"openid"}))
	if _, ok := body["email"]; ok {
		t.Fatalf("email leaked without email scope: %v", body)
	}
}

func TestUserinfoRejectsBadTokens(t *testing.T) {
	s, ts := testServer(t)
	// No token at all:
	if status, _ := getUserinfo(t, ts, ""); status != 401 {
		t.Fatalf("missing token: status = %d", status)
	}
	// Token signed by a different key:
	foreign, _ := jose.SignJWT(jose.NewEdSigner("other-seed"),
		jose.NewObj().Set("iss", "http://127.0.0.1:9111").Set("sub", "user-alice-001").Set("token_use", "access"))
	if status, _ := getUserinfo(t, ts, foreign); status != 401 {
		t.Fatalf("foreign token: status = %d", status)
	}
	// Sending the id_token to userinfo is the classic integration bug;
	// the error message should say exactly that.
	p, _ := s.Issuer.Cfg.Persona("alice")
	idTok, _ := s.Issuer.IDToken(p, "web-app", "", allScopes, s.Issuer.IssueTime())
	status, body := getUserinfo(t, ts, idTok)
	if status != 401 {
		t.Fatalf("id_token as bearer: status = %d", status)
	}
	if !strings.Contains(body["error_description"].(string), "id_token") {
		t.Fatalf("unhelpful error: %v", body)
	}
}

// --- /introspect -----------------------------------------------------------------

func TestIntrospectActiveToken(t *testing.T) {
	s, ts := testServer(t)
	tok := mintAccessToken(t, s, []string{"openid", "email"})
	resp, err := http.PostForm(ts.URL+"/introspect", url.Values{
		"token":         {tok},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := decodeBody(t, resp.Body)
	if out["active"] != true {
		t.Fatalf("active = %v (%v)", out["active"], out)
	}
	if out["sub"] != "user-alice-001" || out["client_id"] != "web-app" {
		t.Errorf("out = %v", out)
	}
}

func TestIntrospectInactiveAndAuthRules(t *testing.T) {
	_, ts := testServer(t)
	// RFC 7662: unknown tokens yield {"active": false}, not an error.
	resp, err := http.PostForm(ts.URL+"/introspect", url.Values{
		"token":         {"garbage"},
		"client_id":     {"web-app"},
		"client_secret": {"s3cret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := decodeBody(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || out["active"] != false {
		t.Fatalf("garbage token: status=%d out=%v", resp.StatusCode, out)
	}
	// But the caller itself must authenticate.
	resp, err = http.PostForm(ts.URL+"/introspect", url.Values{"token": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated introspect: status = %d", resp.StatusCode)
	}
}
