package zdas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// mockGitHubServer returns a test server that simulates GitHub's OAuth and API
// endpoints. It accepts any code as valid and returns the provided user data.
func mockGitHubServer(t *testing.T, user map[string]interface{}, orgs []map[string]interface{}) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "test-token",
			"token_type":   "Bearer",
		})
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})

	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(orgs)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func newTestGitHubProvider(t *testing.T, server *httptest.Server, allowedOrgs []string) *GitHubProvider {
	t.Helper()
	p := NewGitHubProvider(ProviderConfig{
		Name:          "github-test",
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		UsernameField: "login",
		UserIDField:   "id",
		AllowedOrgs:   allowedOrgs,
	})
	p.authBaseURL = server.URL + "/login/oauth/authorize"
	p.tokenBaseURL = server.URL + "/login/oauth/access_token"
	p.apiBaseURL = server.URL + "/user"
	return p
}

func TestGitHubProviderName(t *testing.T) {
	p := NewGitHubProvider(ProviderConfig{Name: "gh", ClientID: "c", ClientSecret: "s"})
	if p.Name() != "gh" {
		t.Errorf("Name() = %q", p.Name())
	}
	if p.Issuer() != "https://github.com" {
		t.Errorf("Issuer() = %q", p.Issuer())
	}
}

func TestGitHubProviderAuthorizeURL(t *testing.T) {
	p := NewGitHubProvider(ProviderConfig{
		Name:         "gh",
		ClientID:     "my-client",
		ClientSecret: "s",
	})
	authURL := p.AuthorizeURL("mystate", "https://zdas/callback")
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Get("client_id") != "my-client" {
		t.Errorf("client_id = %q", u.Query().Get("client_id"))
	}
	if u.Query().Get("state") != "mystate" {
		t.Errorf("state = %q", u.Query().Get("state"))
	}
	if !strings.Contains(u.Query().Get("scope"), "read:user") {
		t.Errorf("scope missing read:user: %q", u.Query().Get("scope"))
	}
}

func TestGitHubProviderExchangeAndIdentify(t *testing.T) {
	user := map[string]interface{}{
		"id":    float64(12345),
		"login": "jsmith",
		"name":  "John Smith",
		"email": "j@example.com",
	}
	server := mockGitHubServer(t, user, nil)
	p := newTestGitHubProvider(t, server, nil)

	identity, err := p.ExchangeAndIdentify(context.Background(), "fake-code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Subject != "12345" {
		t.Errorf("Subject = %q, want 12345", identity.Subject)
	}
	if identity.Username != "jsmith" {
		t.Errorf("Username = %q, want jsmith", identity.Username)
	}
	if identity.Issuer != "https://github.com" {
		t.Errorf("Issuer = %q", identity.Issuer)
	}
}

func TestGitHubProviderOrgCheckPass(t *testing.T) {
	user := map[string]interface{}{
		"id":    float64(1),
		"login": "dev",
	}
	orgs := []map[string]interface{}{
		{"login": "mycompany"},
		{"login": "other-org"},
	}
	server := mockGitHubServer(t, user, orgs)
	p := newTestGitHubProvider(t, server, []string{"mycompany"})

	_, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestGitHubProviderOrgCheckFail(t *testing.T) {
	user := map[string]interface{}{
		"id":    float64(1),
		"login": "outsider",
	}
	orgs := []map[string]interface{}{
		{"login": "some-other-org"},
	}
	server := mockGitHubServer(t, user, orgs)
	p := newTestGitHubProvider(t, server, []string{"mycompany"})

	_, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback")
	if err == nil || !strings.Contains(err.Error(), "not in allowed organization") {
		t.Errorf("expected org check failure, got %v", err)
	}
}

func TestGitHubProviderFieldMapping(t *testing.T) {
	user := map[string]interface{}{
		"id":    float64(99),
		"login": "handle",
		"name":  "Full Name",
		"email": "me@example.com",
	}
	server := mockGitHubServer(t, user, nil)

	// Use name instead of login for username.
	p := newTestGitHubProvider(t, server, nil)
	p.usernameField = "name"
	p.userIDField = "id"

	identity, err := p.ExchangeAndIdentify(context.Background(), "code", "https://zdas/callback")
	if err != nil {
		t.Fatalf("ExchangeAndIdentify: %v", err)
	}
	if identity.Username != "Full Name" {
		t.Errorf("Username = %q, want 'Full Name'", identity.Username)
	}
}

func TestExtractField(t *testing.T) {
	data := map[string]interface{}{
		"str":     "hello",
		"num":     float64(42),
		"missing": nil,
	}
	if got := extractField(data, "str"); got != "hello" {
		t.Errorf("str = %q", got)
	}
	if got := extractField(data, "num"); got != "42" {
		t.Errorf("num = %q", got)
	}
	if got := extractField(data, "nope"); got != "" {
		t.Errorf("nope = %q", got)
	}
}
