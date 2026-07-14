// In-memory grant storage. Authorization codes and refresh tokens are
// deterministic — a counter hashed with the seed — so the Nth code a fresh
// server hands out is always the same string, while still being single-use.
package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// Grant is what an authorization code (or refresh token) redeems into.
type Grant struct {
	ClientID    string
	RedirectURI string
	Persona     string
	Nonce       string
	Scope       []string
	// PKCE parameters captured at /authorize.
	Challenge       string
	ChallengeMethod string
}

// Store holds pending codes and live refresh tokens for one server.
type Store struct {
	mu      sync.Mutex
	seed    string
	seq     int
	codes   map[string]Grant
	refresh map[string]Grant
}

// NewStore builds an empty store keyed to the config seed.
func NewStore(seed string) *Store {
	return &Store{
		seed:    seed,
		codes:   map[string]Grant{},
		refresh: map[string]Grant{},
	}
}

func (s *Store) next(kind string) string {
	s.seq++
	sum := sha256.Sum256([]byte(fmt.Sprintf("personad-%s-v1:%s:%d", kind, s.seed, s.seq)))
	return kind + "_" + hex.EncodeToString(sum[:])[:32]
}

// NewCode records g and returns its single-use authorization code.
func (s *Store) NewCode(g Grant) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := s.next("pc")
	s.codes[code] = g
	return code
}

// TakeCode redeems (and burns) an authorization code.
func (s *Store) TakeCode(code string) (Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.codes[code]
	if ok {
		delete(s.codes, code)
	}
	return g, ok
}

// NewRefresh records g and returns a refresh token.
func (s *Store) NewRefresh(g Grant) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := s.next("pr")
	s.refresh[tok] = g
	return tok
}

// TakeRefresh redeems (and rotates out) a refresh token.
func (s *Store) TakeRefresh(token string) (Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.refresh[token]
	if ok {
		delete(s.refresh, token)
	}
	return g, ok
}
