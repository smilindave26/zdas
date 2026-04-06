package zdas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// mockOIDCServer stands up an httptest.Server that serves:
//   - /.well-known/openid-configuration
//   - /jwks
//   - /token  (returns a signed id_token)
//
// It returns the server, a cleanup function, and the server URL.
func mockOIDCServer(t *testing.T, claims map[string]interface{}) (*httptest.Server, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privJWK, err := jwk.FromRaw(privKey)
	if err != nil {
		t.Fatalf("wrap private key: %v", err)
	}
	_ = privJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256)

	pubJWK, err := jwk.FromRaw(privKey.Public())
	if err != nil {
		t.Fatalf("wrap public key: %v", err)
	}
	_ = pubJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.ES256)

	// We need a mux that knows its own URL, which is a chicken-and-egg problem
	// with httptest. We'll use a handler that reads the Host header.
	var server *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		baseURL := server.URL
		doc := map[string]interface{}{
			"issuer":                 baseURL,
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
			"jwks_uri":               baseURL + "/jwks",
			"response_types_supported": []string{"code"},
			"subject_types_supported":  []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		set := jwk.NewSet()
		_ = set.AddKey(pubJWK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Build and sign an ID token with the test claims.
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, server.URL)
		_ = tok.Set(jwt.AudienceKey, "test-client")
		_ = tok.Set(jwt.IssuedAtKey, time.Now())
		_ = tok.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute))
		for k, v := range claims {
			_ = tok.Set(k, v)
		}

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privJWK))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := map[string]interface{}{
			"access_token": "opaque-at",
			"id_token":     string(signed),
			"token_type":   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, privJWK
}

func TestOIDCProviderAuthorizeURL(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]interface{}{"sub": "u123"})

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	authURL := p.AuthorizeURL("state-abc", "https://zdas/callback")
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	if !strings.HasPrefix(authURL, server.URL+"/authorize") {
		t.Errorf("authorize URL prefix wrong: %s", authURL)
	}
	if u.Query().Get("client_id") != "test-client" {
		t.Errorf("client_id = %q", u.Query().Get("client_id"))
	}
	if u.Query().Get("state") != "state-abc" {
		t.Errorf("state = %q", u.Query().Get("state"))
	}
	if u.Query().Get("redirect_uri") != "https://zdas/callback" {
		t.Errorf("redirect_uri = %q", u.Query().Get("redirect_uri"))
	}
}

func TestOIDCProviderAuthorizeURLWithPKCE(t *testing.T) {
	server, _ := mockOIDCServer(t, map[string]interface{}{"sub": "u123"})

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	authURL, verifier, err := p.AuthorizeURLWithPKCE("state-abc", "https://zdas/callback")
	if err != nil {
		t.Fatalf("AuthorizeURLWithPKCE: %v", err)
	}
	if verifier == "" {
		t.Error("verifier is empty")
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	if u.Query().Get("code_challenge") == "" {
		t.Error("missing code_challenge")
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", u.Query().Get("code_challenge_method"))
	}
}

func TestOIDCProviderExchangeAndIdentify(t *testing.T) {
	claims := map[string]interface{}{
		"sub":                "user-42",
		"preferred_username": "jsmith",
		"name":               "John Smith",
	}
	server, _ := mockOIDCServer(t, claims)

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	// Replace the token exchange function to hit the mock server directly.
	origExchange := oidcTokenExchange
	t.Cleanup(func() { oidcTokenExchange = origExchange })
	// Use the default (real HTTP), since our mock server handles /token.

	identity, err := p.ExchangeAndIdentify(ctx, "fake-code", server.URL+"/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Subject != "user-42" {
		t.Errorf("Subject = %q", identity.Subject)
	}
	if identity.Username != "jsmith" {
		t.Errorf("Username = %q, want jsmith", identity.Username)
	}
	if identity.Issuer != server.URL {
		t.Errorf("Issuer = %q", identity.Issuer)
	}
}

func TestOIDCProviderUsernameFallback(t *testing.T) {
	// No preferred_username - should fall back to name.
	claims := map[string]interface{}{
		"sub":  "user-99",
		"name": "Fallback Name",
	}
	server, _ := mockOIDCServer(t, claims)

	ctx := context.Background()
	p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
		Name:     "test-idp",
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	identity, err := p.ExchangeAndIdentify(ctx, "fake-code", server.URL+"/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Username != "Fallback Name" {
		t.Errorf("Username = %q, want 'Fallback Name'", identity.Username)
	}
}

func TestGeneratePKCE(t *testing.T) {
	v1, c1, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	v2, c2, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	if v1 == v2 {
		t.Error("two PKCE verifiers should differ")
	}
	if c1 == c2 {
		t.Error("two PKCE challenges should differ")
	}
	if len(v1) < 40 {
		t.Errorf("verifier too short: %d chars", len(v1))
	}
}
