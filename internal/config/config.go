// Package config loads and validates persona files — the TOML documents
// that define the issuer, the seed, registered clients and user personas.
// Every rejection carries the offending key so a broken CI fixture fails
// with a message, not a mystery.
package config

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/JaydenCJ/personad/internal/toml"
)

// Config is a fully validated persona file.
type Config struct {
	// Issuer is the OIDC issuer URL, e.g. "http://127.0.0.1:9111".
	Issuer string
	// Seed deterministically derives the Ed25519 signing key.
	Seed string
	// Algorithm is "EdDSA" (default) or "RS256".
	Algorithm string
	// RSAKeyFile is the PEM key path, required when Algorithm is RS256.
	RSAKeyFile string
	// TTL is the access/ID token lifetime.
	TTL time.Duration
	// IssuedAt, when set, freezes iat/exp so token bytes are stable.
	IssuedAt *time.Time
	Clients  []Client
	Personas []Persona
}

// Client is a registered OAuth2/OIDC client.
type Client struct {
	ID           string
	Secret       string // empty = public client (PKCE required)
	RedirectURIs []string
}

// Persona is a canned user identity.
type Persona struct {
	Name          string // handle used on the CLI and ?persona= param
	Subject       string // the "sub" claim
	Email         string
	EmailVerified bool
	Groups        []string
	// Claims are arbitrary extra claims, emitted sorted by key.
	Claims map[string]any
}

// Defaults applied when the persona file omits a key.
const (
	DefaultAlgorithm = "EdDSA"
	DefaultTTL       = time.Hour
)

// LoadFile reads and validates a persona file from disk.
func LoadFile(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Load(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Load parses and validates persona-file source.
func Load(src string) (*Config, error) {
	tree, err := toml.Parse(src)
	if err != nil {
		return nil, err
	}
	d := &decoder{}
	d.allow(tree, "top level", "issuer", "seed", "tokens", "clients", "personas")
	cfg := &Config{
		Issuer:     d.str(tree, "issuer", ""),
		Seed:       d.str(tree, "seed", ""),
		Algorithm:  DefaultAlgorithm,
		TTL:        DefaultTTL,
		RSAKeyFile: "",
	}

	if tokens, ok := tree["tokens"]; ok {
		tt, ok := tokens.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("config: [tokens] must be a table")
		}
		d.allow(tt, "tokens", "algorithm", "ttl", "issued_at", "rsa_key_file")
		cfg.Algorithm = d.str(tt, "algorithm", DefaultAlgorithm)
		cfg.RSAKeyFile = d.str(tt, "rsa_key_file", "")
		if s := d.str(tt, "ttl", ""); s != "" {
			ttl, err := time.ParseDuration(s)
			if err != nil || ttl <= 0 {
				return nil, fmt.Errorf("config: tokens.ttl %q is not a positive duration (try \"1h\", \"90m\")", s)
			}
			cfg.TTL = ttl
		}
		if s := d.str(tt, "issued_at", ""); s != "" {
			at, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return nil, fmt.Errorf("config: tokens.issued_at %q is not an RFC 3339 timestamp", s)
			}
			at = at.UTC()
			cfg.IssuedAt = &at
		}
	}

	clients, err := d.tables(tree, "clients")
	if err != nil {
		return nil, err
	}
	for i, ct := range clients {
		d.allow(ct, fmt.Sprintf("clients[%d]", i), "client_id", "client_secret", "redirect_uris")
		c := Client{
			ID:           d.str(ct, "client_id", ""),
			Secret:       d.str(ct, "client_secret", ""),
			RedirectURIs: d.strs(ct, "redirect_uris"),
		}
		cfg.Clients = append(cfg.Clients, c)
	}

	personas, err := d.tables(tree, "personas")
	if err != nil {
		return nil, err
	}
	for i, pt := range personas {
		d.allow(pt, fmt.Sprintf("personas[%d]", i),
			"name", "subject", "email", "email_verified", "groups", "claims")
		p := Persona{
			Name:          d.str(pt, "name", ""),
			Subject:       d.str(pt, "subject", ""),
			Email:         d.str(pt, "email", ""),
			EmailVerified: d.boolean(pt, "email_verified", false),
			Groups:        d.strs(pt, "groups"),
		}
		if raw, ok := pt["claims"]; ok {
			claims, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("config: personas[%d].claims must be a table", i)
			}
			p.Claims = claims
		}
		cfg.Personas = append(cfg.Personas, p)
	}

	if d.err != nil {
		return nil, d.err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// reservedClaims may not be overridden by persona claim tables: they are
// computed by the issuer and overriding them would make tokens lie.
var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"nonce": true, "jti": true, "auth_time": true, "azp": true,
	"client_id": true, "scope": true, "token_use": true,
}

func (c *Config) validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("config: issuer is required (e.g. \"http://127.0.0.1:9111\")")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: issuer %q must be an absolute http(s) URL", c.Issuer)
	}
	if strings.HasSuffix(u.Path, "/") && u.Path != "" {
		return fmt.Errorf("config: issuer %q must not end with a slash (OIDC discovery rule)", c.Issuer)
	}
	if c.Seed == "" {
		return fmt.Errorf("config: seed is required; it deterministically derives the signing key")
	}
	switch c.Algorithm {
	case "EdDSA":
		if c.RSAKeyFile != "" {
			return fmt.Errorf("config: tokens.rsa_key_file is only used with tokens.algorithm = \"RS256\"")
		}
	case "RS256":
		if c.RSAKeyFile == "" {
			return fmt.Errorf("config: tokens.algorithm = \"RS256\" requires tokens.rsa_key_file")
		}
	default:
		return fmt.Errorf("config: tokens.algorithm %q is not supported (use \"EdDSA\" or \"RS256\")", c.Algorithm)
	}

	if len(c.Clients) == 0 {
		return fmt.Errorf("config: at least one [[clients]] entry is required")
	}
	seenClient := map[string]bool{}
	for i, cl := range c.Clients {
		if cl.ID == "" {
			return fmt.Errorf("config: clients[%d].client_id is required", i)
		}
		if seenClient[cl.ID] {
			return fmt.Errorf("config: client_id %q is defined twice", cl.ID)
		}
		seenClient[cl.ID] = true
		if len(cl.RedirectURIs) == 0 {
			return fmt.Errorf("config: client %q needs at least one redirect_uris entry", cl.ID)
		}
		for _, r := range cl.RedirectURIs {
			ru, err := url.Parse(r)
			if err != nil || !ru.IsAbs() {
				return fmt.Errorf("config: client %q redirect URI %q is not an absolute URL", cl.ID, r)
			}
			if ru.Fragment != "" {
				return fmt.Errorf("config: client %q redirect URI %q must not contain a fragment", cl.ID, r)
			}
		}
	}

	if len(c.Personas) == 0 {
		return fmt.Errorf("config: at least one [[personas]] entry is required")
	}
	seenName, seenSub := map[string]bool{}, map[string]bool{}
	for i, p := range c.Personas {
		if p.Name == "" {
			return fmt.Errorf("config: personas[%d].name is required", i)
		}
		if p.Subject == "" {
			return fmt.Errorf("config: persona %q needs a subject (the \"sub\" claim)", p.Name)
		}
		if seenName[p.Name] {
			return fmt.Errorf("config: persona name %q is defined twice", p.Name)
		}
		if seenSub[p.Subject] {
			return fmt.Errorf("config: persona subject %q is defined twice", p.Subject)
		}
		seenName[p.Name] = true
		seenSub[p.Subject] = true
		for k, v := range p.Claims {
			if reservedClaims[k] {
				return fmt.Errorf("config: persona %q claim %q is reserved and computed by the issuer", p.Name, k)
			}
			if err := validClaimValue(v); err != nil {
				return fmt.Errorf("config: persona %q claim %q: %w", p.Name, k, err)
			}
		}
	}
	return nil
}

// validClaimValue restricts custom claims to JSON-representable scalars and
// arrays of scalars — nested tables would be legal JSON but are rejected in
// 0.1.0 to keep token snapshots easy to eyeball.
func validClaimValue(v any) error {
	switch t := v.(type) {
	case string, bool, int64, float64:
		return nil
	case []any:
		for _, e := range t {
			switch e.(type) {
			case string, bool, int64, float64:
			default:
				return fmt.Errorf("arrays may only contain strings, numbers and booleans")
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported claim type %T", v)
	}
}

// Persona looks a persona up by its handle.
func (c *Config) Persona(name string) (*Persona, bool) {
	for i := range c.Personas {
		if c.Personas[i].Name == name {
			return &c.Personas[i], true
		}
	}
	return nil, false
}

// Client looks a client up by client_id.
func (c *Config) Client(id string) (*Client, bool) {
	for i := range c.Clients {
		if c.Clients[i].ID == id {
			return &c.Clients[i], true
		}
	}
	return nil, false
}

// RedirectAllowed reports whether uri exactly matches a registered redirect.
func (cl *Client) RedirectAllowed(uri string) bool {
	for _, r := range cl.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}

// PersonaNames returns all persona handles in file order.
func (c *Config) PersonaNames() []string {
	names := make([]string, len(c.Personas))
	for i, p := range c.Personas {
		names[i] = p.Name
	}
	return names
}

// SortedClaimKeys returns the persona's custom claim keys sorted, for
// deterministic listings.
func (p *Persona) SortedClaimKeys() []string {
	keys := make([]string, 0, len(p.Claims))
	for k := range p.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// decoder accumulates the first type error seen while walking the tree.
type decoder struct{ err error }

func (d *decoder) fail(format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("config: "+format, args...)
	}
}

func (d *decoder) str(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok {
		d.fail("%s must be a string, got %s", key, tomlType(v))
		return def
	}
	return s
}

func (d *decoder) boolean(m map[string]any, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	b, ok := v.(bool)
	if !ok {
		d.fail("%s must be true or false, got %s", key, tomlType(v))
		return def
	}
	return b
}

func (d *decoder) strs(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		d.fail("%s must be an array of strings, got %s", key, tomlType(v))
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			d.fail("%s must contain only strings, found %s", key, tomlType(e))
			return nil
		}
		out = append(out, s)
	}
	return out
}

func (d *decoder) tables(m map[string]any, key string) ([]map[string]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("config: %s must be an array of tables ([[%s]])", key, key)
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		t, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("config: %s must be an array of tables ([[%s]])", key, key)
		}
		out = append(out, t)
	}
	return out, nil
}

// allow flags unknown keys — typos in persona files should fail loudly, not
// silently mint tokens without the claim you thought you configured.
func (d *decoder) allow(m map[string]any, where string, keys ...string) {
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	var unknown []string
	for k := range m {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		d.fail("%s has unknown key %q (allowed: %s)", where, unknown[0], strings.Join(keys, ", "))
	}
}

func tomlType(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int64:
		return "an integer"
	case float64:
		return "a float"
	case []any:
		return "an array"
	case map[string]any:
		return "a table"
	default:
		return fmt.Sprintf("%T", v)
	}
}
