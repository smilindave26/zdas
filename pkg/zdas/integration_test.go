package zdas

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TestIntegrationOIDCFlow tests the complete authorize -> callback -> token
// flow using a mock Ziti controller and a mock OIDC provider.
func TestIntegrationOIDCFlow(t *testing.T) {
	// 1. Stand up a mock OIDC IdP.
	idpClaims := map[string]interface{}{
		"sub":                "oidc-user-42",
		"preferred_username": "alice",
		"name":               "Alice Smith",
	}
	idpServer, _ := mockOIDCServer(t, idpClaims)

	// 2. Stand up a mock Ziti controller that returns the IdP as a signer.
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		resp := signerResponse{Data: []signerEntry{
			{
				Name:                "test-keycloak",
				Issuer:              idpServer.URL,
				ClientID:            "test-client",
				ExternalAuthURL:     idpServer.URL + "/authorize",
				EnrollToCertEnabled: true,
			},
		}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)

	// 3. Build a ZDAS server with this config.
	cfg := Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:       ctrlServer.URL,
			PollInterval: 0,
			SelfIssuer:   "https://zdas.test",
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Run initial discovery (discovers the OIDC provider).
	if err := srv.discovery.RunOnce(t.Context()); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	t.Cleanup(func() {
		srv.store.Stop()
	})

	mux := srv.handlers.Mux()

	// 4. Tunneler sends /authorize.
	verifier, challenge := generateTestPKCE(t)
	authReq := "/authorize?" + url.Values{
		"redirect_uri":          {"https://tunneler/cb"},
		"response_type":         {"code"},
		"state":                 {"tunneler-state-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"macbook-pro"},
		"client_id":             {"ziti-enrolltocert"},
	}.Encode()

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authReq, nil))

	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	upstreamRedirect, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upstream redirect: %v", err)
	}
	if !strings.HasPrefix(upstreamRedirect.String(), idpServer.URL+"/authorize") {
		t.Fatalf("expected redirect to IdP, got %s", upstreamRedirect)
	}
	sessionState := upstreamRedirect.Query().Get("state")
	if sessionState == "" {
		t.Fatal("no state in upstream redirect")
	}

	// 5. Simulate the upstream IdP calling back with an authorization code.
	callbackReq := "/callback?" + url.Values{
		"code":  {"upstream-auth-code"},
		"state": {sessionState},
	}.Encode()

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, callbackReq, nil))

	if w.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", w.Code, w.Body.String())
	}
	tunnelerRedirect, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse tunneler redirect: %v", err)
	}
	if tunnelerRedirect.Query().Get("state") != "tunneler-state-abc" {
		t.Errorf("tunneler state = %q", tunnelerRedirect.Query().Get("state"))
	}
	zdasCode := tunnelerRedirect.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no zdas code in tunneler redirect")
	}

	// 6. Tunneler exchanges the code at /token.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {verifier},
		"client_id":     {"ziti-enrolltocert"},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, tokenReq)

	if w.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", tokenResp["token_type"])
	}

	// 7. Verify the JWT.
	rawJWT := tokenResp["id_token"].(string)
	jwksBytes, _ := srv.keys.PublicJWKS()
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(rawJWT), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	if tok.Issuer() != "https://zdas.test" {
		t.Errorf("issuer = %q", tok.Issuer())
	}
	idName, _ := tok.Get("device_identity_name")
	if idName != "alice-macbook-pro" {
		t.Errorf("device_identity_name = %v", idName)
	}
	extID, _ := tok.Get("device_external_id")
	if extID == nil || extID == "" {
		t.Error("device_external_id missing")
	}
	if tok.Subject() != extID {
		t.Errorf("sub (%q) should equal device_external_id (%q)", tok.Subject(), extID)
	}
	devName, _ := tok.Get("device_name")
	if devName != "macbook-pro" {
		t.Errorf("device_name = %v", devName)
	}
}

// TestIntegrationGitHubFlow tests the flow with a GitHub provider.
func TestIntegrationGitHubFlow(t *testing.T) {
	// Mock GitHub API.
	githubUser := map[string]interface{}{
		"id":    float64(77777),
		"login": "bobdev",
		"name":  "Bob Developer",
	}
	ghServer := mockGitHubServer(t, githubUser, nil)

	// Mock controller with no OIDC signers (only GitHub configured directly).
	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: []signerEntry{}})
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)

	cfg := Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:       ctrlServer.URL,
			PollInterval: 0,
			SelfIssuer:   "https://zdas.test",
		},
		Providers: []ProviderConfig{
			{
				Type:          ProviderTypeGitHub,
				Name:          "github",
				ClientID:      "test-gh-client",
				ClientSecret:  "test-gh-secret",
				UsernameField: "login",
				UserIDField:   "id",
			},
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	srv, err := NewServer(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.discovery.RunOnce(t.Context()); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	t.Cleanup(func() { srv.store.Stop() })

	// Point the GitHub provider at our mock server.
	ghProv, err := srv.registry.Resolve("github")
	if err != nil {
		t.Fatalf("resolve github: %v", err)
	}
	ghp := ghProv.(*GitHubProvider)
	ghp.authBaseURL = ghServer.URL + "/login/oauth/authorize"
	ghp.tokenBaseURL = ghServer.URL + "/login/oauth/access_token"
	ghp.apiBaseURL = ghServer.URL + "/user"

	mux := srv.handlers.Mux()

	// Tunneler sends /authorize.
	verifier, challenge := generateTestPKCE(t)
	authReq := "/authorize?" + url.Values{
		"redirect_uri":          {"https://tunneler/cb"},
		"response_type":         {"code"},
		"state":                 {"gh-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"linux-desktop"},
		"client_id":             {"ziti-enrolltocert"},
	}.Encode()

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authReq, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status = %d", w.Code)
	}
	upstreamRedirect, _ := url.Parse(w.Header().Get("Location"))
	sessionState := upstreamRedirect.Query().Get("state")

	// Simulate GitHub callback.
	callbackReq := "/callback?code=gh-code&state=" + sessionState
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, callbackReq, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", w.Code, w.Body.String())
	}
	tunnelerRedirect, _ := url.Parse(w.Header().Get("Location"))
	zdasCode := tunnelerRedirect.Query().Get("code")

	// Token exchange.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {verifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, tokenReq)
	if w.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &tokenResp)
	rawJWT := tokenResp["id_token"].(string)

	jwksBytes, _ := srv.keys.PublicJWKS()
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(rawJWT), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	idName, _ := tok.Get("device_identity_name")
	if idName != "bobdev-linux-desktop" {
		t.Errorf("device_identity_name = %v, want bobdev-linux-desktop", idName)
	}
	upSub, _ := tok.Get("upstream_sub")
	if upSub != "77777" {
		t.Errorf("upstream_sub = %v, want 77777", upSub)
	}
}

// TestIntegrationFallbackFlow tests enrollment without device_name when
// fallback is enabled. The JWT should have a pending-style name and
// nonce-based external ID.
func TestIntegrationFallbackFlow(t *testing.T) {
	idpClaims := map[string]interface{}{
		"sub":                "fallback-user",
		"preferred_username": "charlie",
	}
	idpServer, _ := mockOIDCServer(t, idpClaims)

	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		resp := signerResponse{Data: []signerEntry{
			{
				Name:                "test-kc",
				Issuer:              idpServer.URL,
				ClientID:            "test-client",
				ExternalAuthURL:     idpServer.URL + "/authorize",
				EnrollToCertEnabled: true,
			},
		}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)

	cfg := Config{
		Listen:      ":0",
		ExternalURL: "https://zdas.test",
		TLS:         TLSConfig{Mode: TLSModeNone},
		Controller: ControllerConfig{
			APIURL:       ctrlServer.URL,
			PollInterval: 0,
			SelfIssuer:   "https://zdas.test",
		},
		Fallback: FallbackConfig{
			Enabled:          true,
			PollInterval:     10 * time.Second,
			TempNameTemplate: "{username}-pending-{nonce_short}",
			Timeout:          1 * time.Hour,
		},
		Claims: ClaimsConfig{
			UsernameClaim:     "preferred_username",
			NameTemplate:      "{username}-{device_name}",
			IdentityNameClaim: "device_identity_name",
			ExternalIDClaim:   "device_external_id",
		},
		Token: TokenConfig{
			Issuer:   "https://zdas.test",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	// Build server components manually (no identity file needed for this test).
	keys, _ := GenerateKeySet()
	registry := NewProviderRegistry()
	store := NewSessionStore(cfg.Session.Timeout, cfg.Session.CodeExpiry)
	t.Cleanup(store.Stop)

	disc, _ := NewDiscovery(cfg.Controller, registry, nil, slog.Default())
	if err := disc.RunOnce(t.Context()); err != nil {
		t.Fatalf("discovery: %v", err)
	}

	// No reconciler in this test (no identity file), but fallback is enabled.
	h := NewHandlers(cfg, keys, registry, store, nil, slog.Default())
	mux := h.Mux()

	// Tunneler sends /authorize WITHOUT device_name.
	verifier, challenge := generateTestPKCE(t)
	authReq := "/authorize?" + url.Values{
		"redirect_uri":          {"https://tunneler/cb"},
		"response_type":         {"code"},
		"state":                 {"fb-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"client_id":             {"ziti-enrolltocert"},
	}.Encode()

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authReq, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	upstreamRedirect, _ := url.Parse(w.Header().Get("Location"))
	if strings.Contains(upstreamRedirect.String(), "error=") {
		t.Fatalf("expected upstream redirect, got error: %s", upstreamRedirect)
	}
	sessionState := upstreamRedirect.Query().Get("state")

	// Simulate upstream callback.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=upstream-code&state="+sessionState, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", w.Code, w.Body.String())
	}
	tunnelerRedirect, _ := url.Parse(w.Header().Get("Location"))
	zdasCode := tunnelerRedirect.Query().Get("code")

	// Token exchange.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {verifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, tokenReq)
	if w.Code != http.StatusOK {
		t.Fatalf("token: status = %d, body = %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &tokenResp)
	rawJWT := tokenResp["id_token"].(string)

	jwksBytes, _ := keys.PublicJWKS()
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(rawJWT), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("verify jwt: %v", err)
	}

	// Verify fallback claims.
	idName, _ := tok.Get("device_identity_name")
	name := idName.(string)
	if !strings.HasPrefix(name, "charlie-pending-") {
		t.Errorf("device_identity_name = %q, want charlie-pending-*", name)
	}
	extID, _ := tok.Get("device_external_id")
	if extID == nil || extID == "" {
		t.Error("device_external_id missing")
	}
	devName, _ := tok.Get("device_name")
	if devName != "" {
		t.Errorf("device_name should be empty for fallback, got %v", devName)
	}
}
