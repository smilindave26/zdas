package zdas

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func setupHandlers(t *testing.T) (*Handlers, *stubProvider) {
	t.Helper()
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	reg := NewProviderRegistry()
	sp := &stubProvider{name: "test-idp", issuer: "https://test-idp"}
	if err := reg.Register(sp); err != nil {
		t.Fatal(err)
	}
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   "https://zdas.example.com",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
	}
	h := NewHandlers(cfg, ks, reg, store, slog.Default())
	return h, sp
}

// generateTestPKCE returns a verifier and its S256 challenge for tests.
func generateTestPKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()
	v, c, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	return v, c
}

func TestHandleDiscovery(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["issuer"] != "https://zdas.example.com" {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["jwks_uri"] != "https://zdas.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
}

func TestHandleJWKS(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Errorf("keys count = %d", len(doc.Keys))
	}
}

func TestHandleAuthorizeMissingDeviceNameFallbackDisabled(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()
	_, challenge := generateTestPKCE(t)

	reqURL := "/authorize?redirect_uri=https://tunneler/cb&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") || !strings.Contains(loc, "device_name") {
		t.Errorf("expected device_name error redirect, got %s", loc)
	}
}

func TestHandleAuthorizeFallbackEnabled(t *testing.T) {
	// Same as setupHandlers but with fallback enabled.
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	sp := &stubProvider{name: "test-idp", issuer: "https://test-idp"}
	_ = reg.Register(sp)
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Fallback:    FallbackConfig{Enabled: true, TempNameTemplate: "{username}-pending-{nonce_short}"},
		Claims:      defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   "https://zdas.example.com",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
	}
	h := NewHandlers(cfg, ks, reg, store, slog.Default())
	mux := h.Mux()

	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=https://tunneler/cb&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should redirect to upstream (not error), even without device_name.
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "error=") {
		t.Errorf("expected upstream redirect, got error: %s", loc)
	}
	if !strings.HasPrefix(loc, "https://stub/test-idp") {
		t.Errorf("expected redirect to stub provider, got %s", loc)
	}
}

func TestHandleAuthorizeMissingPKCE(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()

	reqURL := "/authorize?redirect_uri=https://tunneler/cb&response_type=code&state=s1&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") || !strings.Contains(loc, "PKCE") {
		t.Errorf("expected PKCE error redirect, got %s", loc)
	}
}

func TestHandleAuthorizeRedirects(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()
	_, challenge := generateTestPKCE(t)

	reqURL := "/authorize?redirect_uri=https://tunneler/cb&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://stub/test-idp") {
		t.Errorf("expected redirect to stub provider, got %s", loc)
	}
}

func TestTokenEndpointFullFlow(t *testing.T) {
	// This tests the /token endpoint directly by pre-populating an auth code
	// in the session store (simulating what /callback would have done).
	h, _ := setupHandlers(t)
	mux := h.Mux()

	verifier, challenge := generateTestPKCE(t)

	claims := ComposeClaims(defaultClaimsConfig(), &UpstreamIdentity{
		Subject:  "user1",
		Username: "alice",
		Issuer:   "https://test-idp",
		Raw:      map[string]interface{}{"preferred_username": "alice"},
	}, &DeviceInfo{DeviceName: "macbook"})

	code, err := h.store.CreateCode(&AuthCode{
		Claims:              claims,
		RedirectURI:         "https://tunneler/cb",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {verifier},
		"client_id":     {"ziti-enrolltocert"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", resp["token_type"])
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("access_token is empty")
	}
	if resp["id_token"] == nil || resp["id_token"] == "" {
		t.Error("id_token is empty")
	}
}

func TestTokenEndpointRejectsReplay(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()
	verifier, challenge := generateTestPKCE(t)

	code, _ := h.store.CreateCode(&AuthCode{
		Claims:              map[string]interface{}{"sub": "x"},
		RedirectURI:         "https://tunneler/cb",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {verifier},
	}

	// First exchange.
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first exchange: status = %d", w.Code)
	}

	// Second exchange (replay) should fail.
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want 400", w.Code)
	}
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error = %q", errResp["error"])
	}
}

func TestTokenEndpointBadPKCE(t *testing.T) {
	h, _ := setupHandlers(t)
	mux := h.Mux()
	_, challenge := generateTestPKCE(t)

	code, _ := h.store.CreateCode(&AuthCode{
		Claims:              map[string]interface{}{"sub": "x"},
		RedirectURI:         "https://tunneler/cb",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {"wrong-verifier"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error = %q", errResp["error"])
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier, challenge := generateTestPKCE(t)
	if !verifyPKCE(challenge, "S256", verifier) {
		t.Error("valid PKCE should pass")
	}
	if verifyPKCE(challenge, "S256", "wrong") {
		t.Error("wrong verifier should fail")
	}
	if verifyPKCE(challenge, "plain", verifier) {
		t.Error("non-S256 method should fail")
	}
}

// callbackProvider implements UpstreamProvider for handler callback tests,
// returning a canned identity on ExchangeAndIdentify.
type callbackProvider struct {
	name     string
	issuer   string
	identity *UpstreamIdentity
}

func (p *callbackProvider) Name() string   { return p.name }
func (p *callbackProvider) Issuer() string { return p.issuer }
func (p *callbackProvider) AuthorizeURL(state, redirectURI string) string {
	return "https://idp/authorize?state=" + state
}
func (p *callbackProvider) ExchangeAndIdentify(_ context.Context, code, redirectURI string) (*UpstreamIdentity, error) {
	return p.identity, nil
}

func TestCallbackToTokenFullFlow(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u42",
			Username: "jsmith",
			Issuer:   "https://mock-idp",
			Raw:      map[string]interface{}{"preferred_username": "jsmith"},
		},
	}
	_ = reg.Register(cp)
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token: TokenConfig{
			Issuer:   "https://zdas.example.com",
			Audience: "ziti-enrolltocert",
			Expiry:   5 * time.Minute,
		},
	}
	h := NewHandlers(cfg, ks, reg, store, slog.Default())
	mux := h.Mux()

	// Pre-create a session as if /authorize had run.
	verifier, challenge := generateTestPKCE(t)
	sessID, _ := store.CreateSession(&AuthSession{
		TunnelerRedirectURI:         "https://tunneler/cb",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "macbook"},
		UpstreamProviderName:        "mock-idp",
	})

	// Simulate /callback from upstream.
	callbackURL := "/callback?code=upstream-code&state=" + sessID
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Query().Get("state") != "tstate" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
	zdasCode := loc.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no zdas code in callback redirect")
	}

	// Exchange the ZDAS code at /token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("missing access_token")
	}
}
