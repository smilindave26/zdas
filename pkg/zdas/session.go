package zdas

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// AuthSession holds state for an in-flight authorization flow between the
// /authorize call and the /callback.
type AuthSession struct {
	TunnelerRedirectURI        string
	TunnelerState              string
	TunnelerCodeChallenge      string
	TunnelerCodeChallengeMethod string
	DeviceInfo                 *DeviceInfo // nil when fallback path (unmodified tunneler)
	FallbackNonce              string     // populated only on fallback path
	ZDASCodeVerifier           string     // ZDAS's own PKCE verifier for upstream (empty for non-PKCE providers)
	UpstreamProviderName       string
	CreatedAt                  time.Time
}

// AuthCode holds composed claims alongside the metadata needed to validate the
// tunneler's code exchange request.
type AuthCode struct {
	Claims              map[string]interface{}
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	IsFallback          bool // true if enrolled via fallback path
	CreatedAt           time.Time
	Used                bool
}

// SessionStore is an in-memory store for auth sessions and authorization codes
// with automatic expiration. It is safe for concurrent use.
type SessionStore struct {
	sessionTTL time.Duration
	codeTTL    time.Duration

	mu       sync.Mutex
	sessions map[string]*AuthSession
	codes    map[string]*AuthCode

	stopCleanup chan struct{}
}

// NewSessionStore creates a store with the given TTLs and starts a background
// cleanup goroutine.
func NewSessionStore(sessionTTL, codeTTL time.Duration) *SessionStore {
	s := &SessionStore{
		sessionTTL:  sessionTTL,
		codeTTL:     codeTTL,
		sessions:    make(map[string]*AuthSession),
		codes:       make(map[string]*AuthCode),
		stopCleanup: make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Stop halts the background cleanup goroutine.
func (s *SessionStore) Stop() {
	close(s.stopCleanup)
}

// CreateSession stores a new auth session and returns its ID.
func (s *SessionStore) CreateSession(sess *AuthSession) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	sess.CreatedAt = time.Now()
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return id, nil
}

// GetSession retrieves and deletes (consumes) an auth session by ID. Returns
// nil if expired or not found.
func (s *SessionStore) GetSession(id string) *AuthSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	delete(s.sessions, id)
	if time.Since(sess.CreatedAt) > s.sessionTTL {
		return nil
	}
	return sess
}

// CreateCode stores composed claims under a new authorization code and returns
// the code string.
func (s *SessionStore) CreateCode(ac *AuthCode) (string, error) {
	code, err := randomID()
	if err != nil {
		return "", err
	}
	ac.CreatedAt = time.Now()
	s.mu.Lock()
	s.codes[code] = ac
	s.mu.Unlock()
	return code, nil
}

// ConsumeCode retrieves and marks an authorization code as used. Returns nil if
// the code is expired, already used, or not found.
func (s *SessionStore) ConsumeCode(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok {
		return nil
	}
	if ac.Used || time.Since(ac.CreatedAt) > s.codeTTL {
		delete(s.codes, code)
		return nil
	}
	ac.Used = true
	return ac
}

func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *SessionStore) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.Sub(sess.CreatedAt) > s.sessionTTL {
			delete(s.sessions, id)
		}
	}
	for code, ac := range s.codes {
		if ac.Used || now.Sub(ac.CreatedAt) > s.codeTTL {
			delete(s.codes, code)
		}
	}
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
