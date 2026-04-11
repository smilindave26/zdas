package zdas

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewServerRegistersConfiguredOIDCProvider verifies that an OIDC provider
// declared in ProviderConfig is created and registered during NewServer.
func TestNewServerRegistersConfiguredOIDCProvider(t *testing.T) {
	// Mock OIDC issuer that serves /.well-known/openid-configuration so
	// NewOIDCProvider's discovery call succeeds.
	idpServer, _ := mockOIDCServer(t, map[string]interface{}{"sub": "test"})

	// Mock controller (returns no signers - we're testing the configured path).
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
				Type:          ProviderTypeOIDC,
				Name:          "my-keycloak",
				ClientID:      "test-client",
				OIDCIssuerURL: idpServer.URL,
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
			Audience: "ziti-enroll",
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
	t.Cleanup(func() { srv.store.Stop() })

	// The configured OIDC provider should be in the registry.
	got, err := srv.registry.Resolve("my-keycloak")
	if err != nil {
		t.Fatalf("expected my-keycloak in registry: %v", err)
	}
	if _, ok := got.(*OIDCProvider); !ok {
		t.Errorf("expected *OIDCProvider, got %T", got)
	}
	if got.Name() != "my-keycloak" {
		t.Errorf("Name() = %q", got.Name())
	}
	if got.Issuer() != idpServer.URL {
		t.Errorf("Issuer() = %q, want %q", got.Issuer(), idpServer.URL)
	}
}

// TestNewServerOIDCProviderDiscoveryFailure verifies that a configured OIDC
// provider with an unreachable issuer fails NewServer at startup (fail-fast).
func TestNewServerOIDCProviderDiscoveryFailure(t *testing.T) {
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
				Type:          ProviderTypeOIDC,
				Name:          "broken",
				ClientID:      "c",
				OIDCIssuerURL: "http://127.0.0.1:1", // unreachable
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
			Audience: "ziti-enroll",
			Expiry:   5 * time.Minute,
		},
		Session: SessionConfig{
			Timeout:    10 * time.Minute,
			CodeExpiry: 60 * time.Second,
		},
	}

	_, err := NewServer(cfg, slog.Default())
	if err == nil {
		t.Fatal("expected NewServer to fail when configured OIDC provider is unreachable")
	}
}
