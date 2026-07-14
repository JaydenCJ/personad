// Package oidc implements personad's OpenID Connect provider: deterministic
// token minting (usable without any HTTP server), the authorization-code +
// PKCE flow, discovery, JWKS, userinfo and introspection.
package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/JaydenCJ/personad/internal/config"
	"github.com/JaydenCJ/personad/internal/jose"
)

// Issuer mints tokens for a validated config. All output is a pure function
// of (config, signer, issue time), which is what makes snapshot testing
// possible: freeze the time and the bytes freeze with it.
type Issuer struct {
	Cfg    *config.Config
	Signer jose.Signer
	// Now supplies the wall clock; tests inject a fixed one. When the
	// config freezes issued_at, Now is never consulted — IssueTime wins.
	Now func() time.Time
}

// NewIssuer builds an Issuer with the signer implied by the config.
func NewIssuer(cfg *config.Config, signer jose.Signer) *Issuer {
	return &Issuer{Cfg: cfg, Signer: signer, Now: time.Now}
}

// IssueTime returns the frozen issued_at when configured, else the clock.
func (i *Issuer) IssueTime() time.Time {
	if i.Cfg.IssuedAt != nil {
		return *i.Cfg.IssuedAt
	}
	return i.Now().UTC().Truncate(time.Second)
}

// Scopes personad understands. Anything else is accepted and echoed but
// releases no claims.
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeGroups  = "groups"
)

// SplitScope canonicalizes a space-separated scope string: deduplicated,
// original order preserved.
func SplitScope(scope string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range strings.Fields(scope) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// IDToken mints the ID token for a persona. Claim order is fixed:
// registered claims first, then scope-released persona claims, then custom
// claims sorted by key — so the compact JWT is byte-stable.
func (i *Issuer) IDToken(p *config.Persona, clientID, nonce string, scopes []string, at time.Time) (string, error) {
	c := jose.NewObj().
		Set("iss", i.Cfg.Issuer).
		Set("sub", p.Subject).
		Set("aud", clientID).
		Set("exp", at.Add(i.Cfg.TTL).Unix()).
		Set("iat", at.Unix()).
		Set("auth_time", at.Unix())
	if nonce != "" {
		c.Set("nonce", nonce)
	}
	i.addPersonaClaims(c, p, scopes)
	return jose.SignJWT(i.Signer, c)
}

// AccessToken mints a JWT access token. It carries the same scope-released
// persona claims as the ID token, so resource servers under test can assert
// on groups and custom claims without a userinfo round-trip.
func (i *Issuer) AccessToken(p *config.Persona, clientID string, scopes []string, at time.Time) (string, error) {
	c := jose.NewObj().
		Set("iss", i.Cfg.Issuer).
		Set("sub", p.Subject).
		Set("aud", clientID).
		Set("client_id", clientID).
		Set("exp", at.Add(i.Cfg.TTL).Unix()).
		Set("iat", at.Unix()).
		Set("jti", i.deriveID("jti", p.Subject, clientID, fmt.Sprint(at.Unix()), strings.Join(scopes, " "))).
		Set("scope", strings.Join(scopes, " ")).
		Set("token_use", "access")
	i.addPersonaClaims(c, p, scopes)
	return jose.SignJWT(i.Signer, c)
}

// ClientCredentialsToken mints an access token for machine-to-machine
// clients: sub == client_id, no persona claims.
func (i *Issuer) ClientCredentialsToken(clientID string, scopes []string, at time.Time) (string, error) {
	c := jose.NewObj().
		Set("iss", i.Cfg.Issuer).
		Set("sub", clientID).
		Set("aud", clientID).
		Set("client_id", clientID).
		Set("exp", at.Add(i.Cfg.TTL).Unix()).
		Set("iat", at.Unix()).
		Set("jti", i.deriveID("jti", clientID, clientID, fmt.Sprint(at.Unix()), strings.Join(scopes, " "))).
		Set("scope", strings.Join(scopes, " ")).
		Set("token_use", "access")
	return jose.SignJWT(i.Signer, c)
}

// addPersonaClaims applies the scope-release rules shared by ID tokens,
// access tokens and userinfo:
//
//	email  → email, email_verified
//	groups → groups
//	profile → every custom claim, sorted by key
func (i *Issuer) addPersonaClaims(c *jose.Obj, p *config.Persona, scopes []string) {
	if hasScope(scopes, ScopeEmail) && p.Email != "" {
		c.Set("email", p.Email)
		c.Set("email_verified", p.EmailVerified)
	}
	if hasScope(scopes, ScopeGroups) && len(p.Groups) > 0 {
		c.Set("groups", p.Groups)
	}
	if hasScope(scopes, ScopeProfile) && len(p.Claims) > 0 {
		c.SetSorted(p.Claims)
	}
}

// UserinfoClaims builds the userinfo response for a persona under scopes.
func (i *Issuer) UserinfoClaims(p *config.Persona, scopes []string) *jose.Obj {
	c := jose.NewObj().Set("sub", p.Subject)
	i.addPersonaClaims(c, p, scopes)
	return c
}

// deriveID produces a short deterministic identifier bound to the seed and
// the given parts. Same config + same inputs → same ID, which keeps whole
// token responses snapshot-friendly.
func (i *Issuer) deriveID(parts ...string) string {
	h := sha256.New()
	h.Write([]byte("personad-id-v1"))
	h.Write([]byte(i.Cfg.Seed))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// Discovery renders the OpenID Provider Metadata document.
func (i *Issuer) Discovery() *jose.Obj {
	iss := i.Cfg.Issuer
	return jose.NewObj().
		Set("issuer", iss).
		Set("authorization_endpoint", iss+"/authorize").
		Set("token_endpoint", iss+"/token").
		Set("userinfo_endpoint", iss+"/userinfo").
		Set("jwks_uri", iss+"/jwks.json").
		Set("introspection_endpoint", iss+"/introspect").
		Set("response_types_supported", []string{"code"}).
		Set("grant_types_supported", []string{"authorization_code", "refresh_token", "client_credentials"}).
		Set("subject_types_supported", []string{"public"}).
		Set("id_token_signing_alg_values_supported", []string{i.Signer.Alg()}).
		Set("scopes_supported", []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeGroups}).
		Set("token_endpoint_auth_methods_supported", []string{"client_secret_basic", "client_secret_post", "none"}).
		Set("code_challenge_methods_supported", []string{"S256", "plain"}).
		Set("claims_supported", i.claimsSupported())
}

// claimsSupported aggregates the registered claims plus every claim any
// persona can release, sorted for stable discovery documents.
func (i *Issuer) claimsSupported() []string {
	set := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
		"auth_time": true, "nonce": true,
	}
	for _, p := range i.Cfg.Personas {
		if p.Email != "" {
			set["email"] = true
			set["email_verified"] = true
		}
		if len(p.Groups) > 0 {
			set["groups"] = true
		}
		for k := range p.Claims {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// JWKS renders the provider's key set.
func (i *Issuer) JWKS() *jose.Obj {
	return jose.JWKS(i.Signer)
}
