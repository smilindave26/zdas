package zdas

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockControllerAndIDPs sets up:
//   - a mock Ziti controller that returns the given signer entries
//   - for each signer entry, a mock OIDC discovery server (if the issuer is
//     left as "", it gets filled in automatically from the mock server URL)
//
// Returns the controller server and a list of OIDC mock servers.
func mockControllerAndIDPs(t *testing.T, signers []signerEntry) (*httptest.Server, []*httptest.Server) {
	t.Helper()

	// Start mock OIDC servers for any signers that need one.
	var idpServers []*httptest.Server
	for i := range signers {
		if !signers[i].EnrollToCertEnabled {
			continue
		}
		idpServer, _ := mockOIDCServer(t, map[string]interface{}{"sub": "testuser"})
		idpServers = append(idpServers, idpServer)
		if signers[i].Issuer == "" {
			signers[i].Issuer = idpServer.URL
		}
	}

	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/edge/client/v1/external-jwt-signers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signerResponse{Data: signers})
	})
	ctrlMux.HandleFunc("/network-jwts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"token":"mock-network-jwt"}]}`))
	})
	ctrlServer := httptest.NewServer(ctrlMux)
	t.Cleanup(ctrlServer.Close)
	return ctrlServer, idpServers
}

func TestDiscoveryRunOnce(t *testing.T) {
	signers := []signerEntry{
		{Name: "keycloak", ClientID: "kc-client", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{
		APIURL:     ctrl.URL,
		SelfIssuer: "https://zdas.example.com",
	}, reg, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}

	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if reg.Len() != 1 {
		t.Fatalf("expected 1 provider, got %d: %v", reg.Len(), reg.Names())
	}
	p, err := reg.Resolve("keycloak")
	if err != nil {
		t.Fatalf("Resolve keycloak: %v", err)
	}
	if p.Name() != "keycloak" {
		t.Errorf("name = %q", p.Name())
	}
}

func TestDiscoveryExcludesSelf(t *testing.T) {
	// One signer is ZDAS itself (matching self_issuer), one is a real IdP.
	selfIssuer := "https://zdas.example.com"
	signers := []signerEntry{
		{Name: "zdas-signer", Issuer: selfIssuer, ClientID: "c", EnrollToCertEnabled: true},
		{Name: "keycloak", ClientID: "kc-client", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{
		APIURL:     ctrl.URL,
		SelfIssuer: selfIssuer,
	}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if reg.Len() != 1 {
		t.Fatalf("expected 1 provider (self excluded), got %d: %v", reg.Len(), reg.Names())
	}
	if _, err := reg.Resolve("zdas-signer"); err == nil {
		t.Error("zdas-signer should have been excluded")
	}
}

func TestDiscoveryFiltersNonEnrollToCert(t *testing.T) {
	signers := []signerEntry{
		{Name: "auth-only", ClientID: "c", Issuer: "https://auth-only", EnrollToCertEnabled: false},
		{Name: "enroll", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("expected 1 provider, got %d", reg.Len())
	}
}

func TestDiscoveryNameCollisionWithConfigured(t *testing.T) {
	signers := []signerEntry{
		{Name: "github", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	configured := map[string]struct{}{"github": {}}
	// Pre-register the configured provider.
	_ = reg.Register(&stubProvider{name: "github", issuer: "https://github.com"})

	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, configured, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	err = d.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Errorf("expected collision error, got %v", err)
	}
}

func TestDiscoveryCachesNetworkJWTs(t *testing.T) {
	signers := []signerEntry{
		{Name: "kc", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl, _ := mockControllerAndIDPs(t, signers)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if d.NetworkJWTsBody() != nil {
		t.Error("expected nil before first poll")
	}
	if err := d.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	body := d.NetworkJWTsBody()
	if body == nil {
		t.Fatal("expected cached network JWTs after poll")
	}
	if !strings.Contains(string(body), "mock-network-jwt") {
		t.Errorf("unexpected cached body: %s", body)
	}
}

func TestDiscoveryControllerUnreachable(t *testing.T) {
	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{APIURL: "http://127.0.0.1:1"}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	err = d.RunOnce(context.Background())
	if err == nil {
		t.Error("expected error for unreachable controller")
	}
}

func TestDiscoveryRefreshReplacesOIDCProviders(t *testing.T) {
	// First poll discovers "kc-old".
	signers1 := []signerEntry{
		{Name: "kc-old", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl1, _ := mockControllerAndIDPs(t, signers1)

	reg := NewProviderRegistry()
	d, err := NewDiscovery(ControllerConfig{APIURL: ctrl1.URL}, reg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("after first poll: %d providers", reg.Len())
	}

	// Second poll discovers "kc-new" instead. Simulate by re-creating with new ctrl.
	signers2 := []signerEntry{
		{Name: "kc-new", ClientID: "c", EnrollToCertEnabled: true},
	}
	ctrl2, _ := mockControllerAndIDPs(t, signers2)
	d.cfg.APIURL = ctrl2.URL

	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("after second poll: expected 1, got %d: %v", reg.Len(), reg.Names())
	}
	if _, err := reg.Resolve("kc-new"); err != nil {
		t.Error("kc-new should exist after refresh")
	}
	if _, err := reg.Resolve("kc-old"); err == nil {
		t.Error("kc-old should have been replaced")
	}
}
