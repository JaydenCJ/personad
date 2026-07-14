// HTTP server: discovery, JWKS, /authorize (code + PKCE), /token,
// /userinfo, /introspect and a health probe. Handlers hold no state beyond
// the Store, and every JSON body is emitted with a fixed key order so
// integration tests can snapshot whole responses.
package oidc

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/JaydenCJ/personad/internal/config"
	"github.com/JaydenCJ/personad/internal/jose"
	"github.com/JaydenCJ/personad/internal/version"
)

// Server wires an Issuer and a Store into an http.Handler.
type Server struct {
	Issuer *Issuer
	Store  *Store
}

// NewServer builds a Server for a validated config.
func NewServer(iss *Issuer) *Server {
	return &Server{Issuer: iss, Store: NewStore(iss.Cfg.Seed)}
}

// Handler returns the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/userinfo", s.handleUserinfo)
	mux.HandleFunc("/introspect", s.handleIntrospect)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// --- shared helpers -------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body *jose.Obj) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body.EncodeIndent())
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, jose.NewObj().
		Set("error", code).
		Set("error_description", desc))
}

// --- metadata endpoints ---------------------------------------------------

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Issuer.Discovery())
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Issuer.JWKS())
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, jose.NewObj().
		Set("status", "ok").
		Set("version", version.Version).
		Set("issuer", s.Issuer.Cfg.Issuer).
		Set("personas", len(s.Issuer.Cfg.Personas)))
}

// --- /authorize -----------------------------------------------------------

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use GET or POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form data")
		return
	}
	q := r.Form

	// Client and redirect URI must be valid before anything is redirected —
	// redirecting errors to an unregistered URI is an open redirect.
	client, ok := s.Issuer.Cfg.Client(q.Get("client_id"))
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("unknown client_id %q", q.Get("client_id")))
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !client.RedirectAllowed(redirectURI) {
		oauthError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("redirect_uri %q is not registered for client %q", redirectURI, client.ID))
		return
	}

	redirectErr := func(code, desc string) {
		s.redirect(w, r, redirectURI, url.Values{
			"error":             {code},
			"error_description": {desc},
			"state":             {q.Get("state")},
		})
	}

	if q.Get("response_type") != "code" {
		redirectErr("unsupported_response_type", "personad only supports response_type=code")
		return
	}
	scopes := SplitScope(q.Get("scope"))
	if !hasScope(scopes, ScopeOpenID) {
		redirectErr("invalid_scope", "scope must include \"openid\"")
		return
	}
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if !ValidChallengeMethod(method) {
		redirectErr("invalid_request", fmt.Sprintf("unsupported code_challenge_method %q", method))
		return
	}
	if challenge == "" && client.Secret == "" {
		redirectErr("invalid_request", "public clients must send a PKCE code_challenge")
		return
	}
	if challenge == "" && method != "" {
		redirectErr("invalid_request", "code_challenge_method sent without code_challenge")
		return
	}

	personaName := q.Get("persona")
	if personaName == "" {
		s.renderPicker(w, r)
		return
	}
	persona, ok := s.Issuer.Cfg.Persona(personaName)
	if !ok {
		redirectErr("access_denied", fmt.Sprintf("unknown persona %q", personaName))
		return
	}

	code := s.Store.NewCode(Grant{
		ClientID:        client.ID,
		RedirectURI:     redirectURI,
		Persona:         persona.Name,
		Nonce:           q.Get("nonce"),
		Scope:           scopes,
		Challenge:       challenge,
		ChallengeMethod: method,
	})
	s.redirect(w, r, redirectURI, url.Values{
		"code":  {code},
		"state": {q.Get("state")},
	})
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, base string, params url.Values) {
	u, _ := url.Parse(base) // validated against the registered list already
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			if v != "" || k == "code" {
				q.Set(k, v)
			}
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// renderPicker serves the persona chooser: the interactive stand-in for a
// login page when a human is driving a browser through the flow.
func (s *Server) renderPicker(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=\"utf-8\"><title>personad — pick a persona</title>")
	b.WriteString("<style>body{font-family:system-ui,sans-serif;max-width:38rem;margin:4rem auto;padding:0 1rem}li{margin:.5rem 0}</style>")
	b.WriteString("<h1>personad</h1><p>Sign in as:</p><ul>")
	for _, p := range s.Issuer.Cfg.Personas {
		q := r.Form
		q.Set("persona", p.Name)
		href := "/authorize?" + q.Encode()
		b.WriteString(fmt.Sprintf("<li><a href=\"%s\">%s</a> <small>(sub: %s)</small></li>",
			html.EscapeString(href), html.EscapeString(p.Name), html.EscapeString(p.Subject)))
	}
	b.WriteString("</ul>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// --- /token -----------------------------------------------------------------

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form data")
		return
	}
	client, authed, errCode := s.authenticateClient(r)
	if errCode != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="personad"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", errCode)
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r, client, authed)
	case "refresh_token":
		s.grantRefreshToken(w, r, client)
	case "client_credentials":
		if !authed {
			oauthError(w, http.StatusBadRequest, "invalid_grant",
				"client_credentials requires a confidential client")
			return
		}
		s.grantClientCredentials(w, r, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("unsupported grant_type %q", r.PostForm.Get("grant_type")))
	}
}

// authenticateClient resolves the client from Basic auth or form fields.
// Returns (client, authenticatedWithSecret, errorDescription).
func (s *Server) authenticateClient(r *http.Request) (*config.Client, bool, string) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		// RFC 6749 §2.3.1: credentials are form-urlencoded inside Basic auth.
		du, err1 := url.QueryUnescape(u)
		dp, err2 := url.QueryUnescape(p)
		if err1 != nil || err2 != nil {
			return nil, false, "malformed Basic auth credentials"
		}
		id, secret = du, dp
	}
	if id == "" {
		return nil, false, "missing client_id"
	}
	client, ok := s.Issuer.Cfg.Client(id)
	if !ok {
		return nil, false, fmt.Sprintf("unknown client_id %q", id)
	}
	if client.Secret == "" {
		// Public client: no secret to check; PKCE carries the proof.
		if secret != "" {
			return nil, false, fmt.Sprintf("client %q is public and has no secret", id)
		}
		return client, false, ""
	}
	if secret == "" {
		return nil, false, fmt.Sprintf("client %q requires a client_secret", id)
	}
	if secret != client.Secret {
		return nil, false, "client_secret mismatch"
	}
	return client, true, ""
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request, client *config.Client, authed bool) {
	code := r.PostForm.Get("code")
	grant, ok := s.Store.TakeCode(code)
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or already-used code")
		return
	}
	if grant.ClientID != client.ID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client")
		return
	}
	if r.PostForm.Get("redirect_uri") != grant.RedirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if grant.Challenge != "" {
		if !VerifyPKCE(grant.Challenge, grant.ChallengeMethod, r.PostForm.Get("code_verifier")) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE code_verifier check failed")
			return
		}
	} else if !authed {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "public client redeemed a code without PKCE")
		return
	}
	s.tokenResponse(w, grant, true)
}

func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request, client *config.Client) {
	grant, ok := s.Store.TakeRefresh(r.PostForm.Get("refresh_token"))
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or rotated refresh_token")
		return
	}
	if grant.ClientID != client.ID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh_token was issued to a different client")
		return
	}
	s.tokenResponse(w, grant, true)
}

func (s *Server) grantClientCredentials(w http.ResponseWriter, r *http.Request, client *config.Client) {
	scopes := SplitScope(r.PostForm.Get("scope"))
	at := s.Issuer.IssueTime()
	access, err := s.Issuer.ClientCredentialsToken(client.ID, scopes, at)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jose.NewObj().
		Set("access_token", access).
		Set("token_type", "Bearer").
		Set("expires_in", int64(s.Issuer.Cfg.TTL.Seconds())).
		Set("scope", strings.Join(scopes, " ")))
}

// tokenResponse mints the access/ID pair for a persona grant and, when
// withRefresh, a rotated refresh token.
func (s *Server) tokenResponse(w http.ResponseWriter, grant Grant, withRefresh bool) {
	persona, ok := s.Issuer.Cfg.Persona(grant.Persona)
	if !ok { // persona removed between authorize and token — config is static, so this is defensive
		oauthError(w, http.StatusBadRequest, "invalid_grant", "persona no longer exists")
		return
	}
	at := s.Issuer.IssueTime()
	access, err := s.Issuer.AccessToken(persona, grant.ClientID, grant.Scope, at)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	idToken, err := s.Issuer.IDToken(persona, grant.ClientID, grant.Nonce, grant.Scope, at)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	body := jose.NewObj().
		Set("access_token", access).
		Set("token_type", "Bearer").
		Set("expires_in", int64(s.Issuer.Cfg.TTL.Seconds()))
	if withRefresh {
		body.Set("refresh_token", s.Store.NewRefresh(grant))
	}
	body.Set("id_token", idToken).
		Set("scope", strings.Join(grant.Scope, " "))
	writeJSON(w, http.StatusOK, body)
}

// --- /userinfo ---------------------------------------------------------------

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use GET or POST")
		return
	}
	tok, desc := s.bearerToken(r)
	if desc != "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description=%q`, desc))
		oauthError(w, http.StatusUnauthorized, "invalid_token", desc)
		return
	}
	persona, ok := s.Issuer.Cfg.Persona(personaBySubject(s.Issuer.Cfg, tok.StringClaim("sub")))
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "token subject is not a persona")
		return
	}
	writeJSON(w, http.StatusOK, s.Issuer.UserinfoClaims(persona, SplitScope(tok.StringClaim("scope"))))
}

// bearerToken extracts and verifies the access token on r.
func (s *Server) bearerToken(r *http.Request) (*jose.Token, string) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return nil, "missing Bearer token"
	}
	tok, err := jose.VerifyJWT(s.Issuer.Signer, strings.TrimPrefix(auth, prefix))
	if err != nil {
		return nil, err.Error()
	}
	if tok.StringClaim("iss") != s.Issuer.Cfg.Issuer {
		return nil, "token issuer mismatch"
	}
	if tok.StringClaim("token_use") != "access" {
		return nil, "not an access token (did you send the id_token?)"
	}
	if tok.IntClaim("exp") < s.Issuer.IssueTime().Unix() {
		return nil, "token is expired"
	}
	return tok, ""
}

func personaBySubject(cfg *config.Config, sub string) string {
	for _, p := range cfg.Personas {
		if p.Subject == sub {
			return p.Name
		}
	}
	return ""
}

// --- /introspect (RFC 7662) ---------------------------------------------------

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form data")
		return
	}
	if _, _, errDesc := s.authenticateClient(r); errDesc != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="personad"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", errDesc)
		return
	}
	tok, err := jose.VerifyJWT(s.Issuer.Signer, r.PostForm.Get("token"))
	inactive := jose.NewObj().Set("active", false)
	if err != nil {
		writeJSON(w, http.StatusOK, inactive)
		return
	}
	if tok.IntClaim("exp") < s.Issuer.IssueTime().Unix() {
		writeJSON(w, http.StatusOK, inactive)
		return
	}
	body := jose.NewObj().
		Set("active", true).
		Set("iss", tok.StringClaim("iss")).
		Set("sub", tok.StringClaim("sub")).
		Set("aud", tok.Claims["aud"]).
		Set("client_id", tok.StringClaim("client_id")).
		Set("exp", tok.IntClaim("exp")).
		Set("iat", tok.IntClaim("iat")).
		Set("scope", tok.StringClaim("scope")).
		Set("token_type", "Bearer")
	writeJSON(w, http.StatusOK, body)
}
