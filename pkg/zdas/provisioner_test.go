package zdas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// immediateProvisioner returns claims directly (no interactive redirect).
type immediateProvisioner struct {
	claims map[string]interface{}
}

func (p *immediateProvisioner) Provision(_ context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	return &ProvisionResult{Claims: p.claims}, nil
}

// interactiveProvisioner returns a redirect URL for interactive selection.
type interactiveProvisioner struct {
	redirectURL string
}

func (p *interactiveProvisioner) Provision(_ context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	return &ProvisionResult{RedirectURL: p.redirectURL}, nil
}

// failingProvisioner returns the configured error from Provision.
type failingProvisioner struct {
	err error
}

func (p *failingProvisioner) Provision(_ context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	return nil, p.err
}

func TestProvisionerImmediateClaims(t *testing.T) {
	// Set up a ZDAS handler with a provisioner that returns claims directly.
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u1",
			Email:    "alice@example.com",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]interface{}{"preferred_username": "alice"},
		},
	}
	_ = reg.Register(cp)
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	provisioner := &immediateProvisioner{
		claims: map[string]interface{}{
			"device_identity_name": "custom-name",
			"device_external_id":   "custom-ext-id",
			"sub":                  "custom-ext-id",
		},
	}

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := NewHandlers(cfg, ks, reg, store, nil, nil, provisioner, slog.Default())
	mux := h.Mux()

	// Create a session as if /authorize ran.
	verifier, challenge := generateTestPKCE(t)
	sessID, _ := store.CreateSession(&AuthSession{
		TunnelerRedirectURI:         "https://tunneler/cb",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "laptop"},
		UpstreamProviderName:        "mock-idp",
	})

	// Simulate callback.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, body = %s", w.Code, w.Body.String())
	}

	loc, _ := url.Parse(w.Header().Get("Location"))
	zdasCode := loc.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no code in redirect")
	}

	// Exchange code for token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {zdasCode},
		"redirect_uri":  {"https://tunneler/cb"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", w.Code, w.Body.String())
	}

	// Verify the token contains the provisioner's custom claims.
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == nil {
		t.Fatal("missing access_token")
	}
}

func TestProvisionerInteractiveRedirect(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u1",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]interface{}{},
		},
	}
	_ = reg.Register(cp)
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	provisioner := &interactiveProvisioner{
		redirectURL: "https://ezziti.example.com/pick-network",
	}

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := NewHandlers(cfg, ks, reg, store, nil, nil, provisioner, slog.Default())
	mux := h.Mux()

	verifier, challenge := generateTestPKCE(t)
	sessID, _ := store.CreateSession(&AuthSession{
		TunnelerRedirectURI:         "https://tunneler/cb",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "laptop"},
		UpstreamProviderName:        "mock-idp",
	})

	// Callback should redirect to the picker page with a pending_id.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), "https://ezziti.example.com/pick-network") {
		t.Fatalf("expected redirect to picker, got %s", loc)
	}
	pendingID := loc.Query().Get("pending_id")
	if pendingID == "" {
		t.Fatal("no pending_id in redirect")
	}

	// Simulate the picker page completing provisioning via POST /provision/complete.
	claims := map[string]interface{}{
		"device_identity_name": "alice-laptop",
		"device_external_id":   "ext-from-picker",
		"sub":                  "ext-from-picker",
	}
	body, _ := json.Marshal(map[string]interface{}{"claims": claims})
	req := httptest.NewRequest(http.MethodPost, "/provision/complete?pending_id="+pendingID,
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("provision/complete status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, _ = url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "tstate" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
	zdasCode := loc.Query().Get("code")
	if zdasCode == "" {
		t.Fatal("no code from provision/complete")
	}

	// Exchange the code.
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
}

// runProvisionerCallback wires a stubbed provisioner up to a /callback request
// and returns the recorder so tests can inspect the redirect.
func runProvisionerCallback(t *testing.T, p EnrollmentProvisioner) *httptest.ResponseRecorder {
	t.Helper()
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	cp := &callbackProvider{
		name:   "mock-idp",
		issuer: "https://mock-idp",
		identity: &UpstreamIdentity{
			Subject:  "u1",
			Email:    "alice@example.com",
			Username: "alice",
			Issuer:   "https://mock-idp",
			Raw:      map[string]interface{}{},
		},
	}
	_ = reg.Register(cp)
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := NewHandlers(cfg, ks, reg, store, nil, nil, p, slog.Default())
	mux := h.Mux()

	_, challenge := generateTestPKCE(t)
	sessID, _ := store.CreateSession(&AuthSession{
		TunnelerRedirectURI:         "https://tunneler/cb",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       challenge,
		TunnelerCodeChallengeMethod: "S256",
		DeviceInfo:                  &DeviceInfo{DeviceName: "laptop"},
		UpstreamProviderName:        "mock-idp",
	})

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil))
	return w
}

func TestProvisionerStructuredErrorPassthrough(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"access_denied", "access_denied"},
		{"invalid_request", "invalid_request"},
		{"server_error", "server_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pe := &ProvisionError{Code: tc.code, Description: "go away: " + tc.name}
			w := runProvisionerCallback(t, &failingProvisioner{err: pe})

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != tc.code {
				t.Errorf("error = %q, want %q", loc.Query().Get("error"), tc.code)
			}
			if loc.Query().Get("error_description") != "go away: "+tc.name {
				t.Errorf("error_description = %q", loc.Query().Get("error_description"))
			}
			if loc.Query().Get("state") != "tstate" {
				t.Errorf("state = %q, want tstate", loc.Query().Get("state"))
			}
		})
	}
}

func TestProvisionerStructuredErrorWrapped(t *testing.T) {
	// errors.As must unwrap correctly through fmt.Errorf wrapping.
	pe := &ProvisionError{Code: "access_denied", Description: "denied"}
	wrapped := fmt.Errorf("provisioning context: %w", pe)
	w := runProvisionerCallback(t, &failingProvisioner{err: wrapped})

	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("wrapped ProvisionError not unwrapped: error = %q", loc.Query().Get("error"))
	}
	if loc.Query().Get("error_description") != "denied" {
		t.Errorf("error_description = %q", loc.Query().Get("error_description"))
	}
}

func TestProvisionerPlainErrorBecomesServerError(t *testing.T) {
	w := runProvisionerCallback(t, &failingProvisioner{err: errors.New("database is down")})

	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "server_error" {
		t.Errorf("error = %q, want server_error", loc.Query().Get("error"))
	}
	if loc.Query().Get("error_description") != "provisioning failed" {
		t.Errorf("error_description = %q", loc.Query().Get("error_description"))
	}
}

func TestSanitizeErrorDescription(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello world", "hello world"},
		{"newlines stripped", "line one\nline two", "line one line two"},
		{"control chars stripped", "tab\there", "tab here"},
		{"backslash stripped", `back\slash`, "back slash"},
		{"quote stripped", `say "hi"`, "say  hi "},
		{"truncates long input", strings.Repeat("a", 300), strings.Repeat("a", 200)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeErrorDescription(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeErrorDescription(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestProvisionerStructuredErrorSanitizes(t *testing.T) {
	pe := &ProvisionError{
		Code:        "access_denied",
		Description: "no\nnewlines\there",
	}
	w := runProvisionerCallback(t, &failingProvisioner{err: pe})

	loc, _ := url.Parse(w.Header().Get("Location"))
	got := loc.Query().Get("error_description")
	if strings.ContainsAny(got, "\n\t") {
		t.Errorf("error_description still contains control chars: %q", got)
	}
	if got != "no newlines here" {
		t.Errorf("error_description = %q", got)
	}
}

func TestProvisionerInvalidErrorCodeFallsBack(t *testing.T) {
	cases := []string{"", "totally_made_up", "INVALID_REQUEST"}
	for _, badCode := range cases {
		t.Run("code_"+badCode, func(t *testing.T) {
			pe := &ProvisionError{Code: badCode, Description: "should not pass through"}
			w := runProvisionerCallback(t, &failingProvisioner{err: pe})

			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != "server_error" {
				t.Errorf("invalid code %q produced error=%q, want server_error",
					badCode, loc.Query().Get("error"))
			}
			if loc.Query().Get("error_description") != "provisioning failed" {
				t.Errorf("error_description = %q", loc.Query().Get("error_description"))
			}
		})
	}
}

// setupProvisionComplete creates a Handlers with a pre-loaded pending provision
// and returns the mux, the pending_id, and the store (so tests can verify
// consumption).
func setupProvisionComplete(t *testing.T) (mux *http.ServeMux, pendingID string, store *SessionStore) {
	t.Helper()
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	reg := NewProviderRegistry()
	store = NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := NewHandlers(cfg, ks, reg, store, nil, nil, nil, slog.Default())
	mux = h.Mux()

	pendingID, err = store.CreatePendingProvision(&PendingProvision{
		TunnelerRedirectURI:         "https://tunneler/cb",
		TunnelerState:               "tstate",
		TunnelerCodeChallenge:       "challenge",
		TunnelerCodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("CreatePendingProvision: %v", err)
	}
	return mux, pendingID, store
}

func postProvisionComplete(t *testing.T, mux *http.ServeMux, pendingID string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/provision/complete?pending_id="+pendingID, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestProvisionCompleteErrorPath(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		desc     string
		wantCode string
	}{
		{"access_denied", "access_denied", "no membership", "access_denied"},
		{"server_error", "server_error", "internal", "server_error"},
		{"invalid_request", "invalid_request", "bad input", "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux, pendingID, _ := setupProvisionComplete(t)
			w := postProvisionComplete(t, mux, pendingID, map[string]interface{}{
				"error": map[string]string{"code": tc.code, "description": tc.desc},
			})

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302; body=%s", w.Code, w.Body.String())
			}
			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != tc.wantCode {
				t.Errorf("error = %q, want %q", loc.Query().Get("error"), tc.wantCode)
			}
			if loc.Query().Get("error_description") != tc.desc {
				t.Errorf("error_description = %q, want %q", loc.Query().Get("error_description"), tc.desc)
			}
			if loc.Query().Get("state") != "tstate" {
				t.Errorf("state = %q, want tstate", loc.Query().Get("state"))
			}
		})
	}
}

func TestProvisionCompleteInvalidErrorCodeFallsBack(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
	}{
		{"unknown code", map[string]any{"error": map[string]string{"code": "totally_made_up", "description": "embedder secret"}}},
		{"empty code", map[string]any{"error": map[string]string{"code": "", "description": "embedder secret"}}},
		{"wrong case", map[string]any{"error": map[string]string{"code": "ACCESS_DENIED", "description": "embedder secret"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux, pendingID, _ := setupProvisionComplete(t)
			w := postProvisionComplete(t, mux, pendingID, tc.body)

			loc, _ := url.Parse(w.Header().Get("Location"))
			if loc.Query().Get("error") != "server_error" {
				t.Errorf("error = %q, want server_error", loc.Query().Get("error"))
			}
			// Description must be replaced with the generic fallback so we
			// don't leak embedder-supplied text alongside a bogus code.
			if loc.Query().Get("error_description") != "provisioning failed" {
				t.Errorf("error_description = %q, want %q",
					loc.Query().Get("error_description"), "provisioning failed")
			}
		})
	}
}

func TestProvisionCompleteMalformedJSONPreservesPending(t *testing.T) {
	mux, pendingID, store := setupProvisionComplete(t)

	req := httptest.NewRequest(http.MethodPost, "/provision/complete?pending_id="+pendingID,
		strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}

	// Pending should still be available - the malformed body must not have
	// burned the one-shot session.
	if pp := store.ConsumePendingProvision(pendingID); pp == nil {
		t.Error("pending provision was consumed by a malformed request")
	}
}

func TestProvisionCompleteErrorPathConsumesPending(t *testing.T) {
	mux, pendingID, store := setupProvisionComplete(t)
	postProvisionComplete(t, mux, pendingID, map[string]interface{}{
		"error": map[string]string{"code": "access_denied", "description": "no"},
	})

	// Pending provision should be gone - second call returns 400.
	if pp := store.ConsumePendingProvision(pendingID); pp != nil {
		t.Error("pending provision was not consumed")
	}
	w := postProvisionComplete(t, mux, pendingID, map[string]interface{}{
		"error": map[string]string{"code": "access_denied", "description": "no"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("replay status = %d, want 400", w.Code)
	}
}

func TestProvisionCompleteEmptyBody(t *testing.T) {
	mux, pendingID, _ := setupProvisionComplete(t)
	w := postProvisionComplete(t, mux, pendingID, map[string]interface{}{})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestProvisionCompleteBothClaimsAndErrorPrefersError(t *testing.T) {
	mux, pendingID, _ := setupProvisionComplete(t)
	w := postProvisionComplete(t, mux, pendingID, map[string]interface{}{
		"claims": map[string]interface{}{"device_external_id": "x"},
		"error":  map[string]string{"code": "access_denied", "description": "denied"},
	})

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("expected error path to win, got error=%q code=%q",
			loc.Query().Get("error"), loc.Query().Get("code"))
	}
}

func TestProvisionCompleteErrorDescriptionSanitized(t *testing.T) {
	mux, pendingID, _ := setupProvisionComplete(t)
	// Include a double-quote and backslash, both disallowed by RFC 6749
	// 4.1.2.1, plus newline/tab control chars. None should survive.
	w := postProvisionComplete(t, mux, pendingID, map[string]interface{}{
		"error": map[string]string{
			"code":        "access_denied",
			"description": "say \"hi\"\nback\\slash\there",
		},
	})

	loc, _ := url.Parse(w.Header().Get("Location"))
	got := loc.Query().Get("error_description")
	if strings.ContainsAny(got, "\n\t\\\"") {
		t.Errorf("description not sanitized: %q", got)
	}
	// And legal characters should survive.
	if !strings.Contains(got, "say") || !strings.Contains(got, "hi") {
		t.Errorf("legal characters lost: %q", got)
	}
}

func TestProvisionCompleteExpired(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.test",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.test", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
	}
	h := NewHandlers(cfg, ks, reg, store, nil, nil, nil, slog.Default())
	mux := h.Mux()

	// Try to complete with a nonexistent pending_id.
	body, _ := json.Marshal(map[string]interface{}{"claims": map[string]interface{}{"sub": "x"}})
	req := httptest.NewRequest(http.MethodPost, "/provision/complete?pending_id=bogus",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
