package zdas

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockManagementAPI simulates the Ziti controller management API for reconciler
// tests. It handles /authenticate, GET /identities (with filter), and PATCH
// /identities/{id}.
type mockManagementAPI struct {
	mu         sync.Mutex
	identities map[string]mockIdentity
	renamed    map[string]string // id -> new name
}

type mockIdentity struct {
	ID         string
	ExternalID string
	Hostname   string // from envInfo
}

func newMockManagementAPI(identities []mockIdentity) *mockManagementAPI {
	m := &mockManagementAPI{
		identities: make(map[string]mockIdentity),
		renamed:    make(map[string]string),
	}
	for _, id := range identities {
		m.identities[id.ExternalID] = id
	}
	return m
}

func (m *mockManagementAPI) setHostname(externalID, hostname string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.identities[externalID]; ok {
		id.Hostname = hostname
		m.identities[externalID] = id
	}
}

func (m *mockManagementAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"token":             "mock-zt-session",
				"expirationSeconds": 1800,
			},
		})
	})
	mux.HandleFunc("/edge/management/v1/identities/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			// Extract identity ID from path.
			parts := strings.Split(r.URL.Path, "/")
			identityID := parts[len(parts)-1]
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.renamed[identityID] = body["name"]
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/edge/management/v1/identities", func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("filter")
		m.mu.Lock()
		defer m.mu.Unlock()

		var results []map[string]interface{}
		for _, id := range m.identities {
			// Simple filter match: check if the externalId is in the filter string.
			if strings.Contains(filter, id.ExternalID) {
				entry := map[string]interface{}{
					"id": id.ID,
				}
				if id.Hostname != "" {
					entry["envInfo"] = map[string]string{"hostname": id.Hostname}
				}
				results = append(results, entry)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": results})
	})
	return mux
}

func TestReconcilerTrack(t *testing.T) {
	r := NewReconciler(
		FallbackConfig{PollInterval: 10 * time.Second, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		http.DefaultClient,
		"https://ctrl",
		slog.Default(),
	)
	r.Track("ext-id-1", "alice", "abc123")
	if r.PendingCount() != 1 {
		t.Fatalf("PendingCount = %d, want 1", r.PendingCount())
	}
	r.Track("ext-id-2", "bob", "def456")
	if r.PendingCount() != 2 {
		t.Fatalf("PendingCount = %d, want 2", r.PendingCount())
	}
}

func TestReconcilerReconcileOneWithHostname(t *testing.T) {
	mock := newMockManagementAPI([]mockIdentity{
		{ID: "id-1", ExternalID: "ext-1", Hostname: "macbook-pro"},
	})
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := NewReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	p := &PendingReconciliation{
		ExternalID: "ext-1",
		Username:   "jsmith",
		Nonce:      "abc123",
		TrackedAt:  time.Now(),
	}
	done, err := r.reconcileOne(t.Context(), p)
	if err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}
	if !done {
		t.Error("expected done=true")
	}
	if mock.renamed["id-1"] != "jsmith-macbook-pro" {
		t.Errorf("renamed to %q, want jsmith-macbook-pro", mock.renamed["id-1"])
	}
}

func TestReconcilerReconcileOneNoHostname(t *testing.T) {
	mock := newMockManagementAPI([]mockIdentity{
		{ID: "id-1", ExternalID: "ext-1", Hostname: ""}, // no envInfo yet
	})
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := NewReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	p := &PendingReconciliation{
		ExternalID: "ext-1",
		Username:   "jsmith",
		TrackedAt:  time.Now(),
	}
	done, err := r.reconcileOne(t.Context(), p)
	if err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}
	if done {
		t.Error("expected done=false (no hostname yet)")
	}
}

func TestReconcilerReconcileOneNotFound(t *testing.T) {
	mock := newMockManagementAPI(nil) // no identities
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := NewReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	p := &PendingReconciliation{
		ExternalID: "nonexistent",
		Username:   "jsmith",
		TrackedAt:  time.Now(),
	}
	done, err := r.reconcileOne(t.Context(), p)
	if err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}
	if done {
		t.Error("expected done=false (not found)")
	}
}

func TestReconcilerTimeout(t *testing.T) {
	mock := newMockManagementAPI(nil)
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := NewReconciler(
		FallbackConfig{PollInterval: 50 * time.Millisecond, Timeout: 1 * time.Millisecond},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	r.sessionToken = "mock-zt-session"
	r.sessionExpires = time.Now().Add(30 * time.Minute)

	r.Track("ext-timeout", "alice", "nonce")
	time.Sleep(5 * time.Millisecond)

	r.poll(t.Context())

	if r.PendingCount() != 0 {
		t.Errorf("expected timed-out entry to be removed, count = %d", r.PendingCount())
	}
}

func TestReconcilerSessionRefresh(t *testing.T) {
	mock := newMockManagementAPI(nil)
	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	r := NewReconciler(
		FallbackConfig{PollInterval: 100 * time.Millisecond, Timeout: 1 * time.Hour},
		defaultClaimsConfig(),
		server.Client(),
		server.URL,
		slog.Default(),
	)
	// Session is expired.
	r.sessionExpires = time.Now().Add(-1 * time.Minute)

	r.Track("ext-1", "alice", "nonce")
	r.poll(t.Context()) // Should trigger refresh.

	if r.sessionToken != "mock-zt-session" {
		t.Errorf("session token not refreshed: %q", r.sessionToken)
	}
}
