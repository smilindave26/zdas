// Package zdastest provides helpers for testing code that embeds zdas.
package zdastest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smilindave26/zdas/pkg/zdas"
)

// TestStore runs a conformance suite against a zdas.Store implementation.
// newStore must return an empty store; it is called once per subtest. The
// suite checks the contract documented on zdas.Store: entries survive a
// round trip with CreatedAt intact, consume is single use for every kind of
// entry, including under concurrency, and a missing key is (nil, nil).
func TestStore(t *testing.T, newStore func(t *testing.T) zdas.Store) {
	t.Run("SessionRoundTrip", func(t *testing.T) {
		s := newStore(t)
		want := &zdas.AuthSession{
			TunnelerRedirectURI:         "https://tunneler/cb",
			TunnelerState:               "tstate",
			TunnelerCodeChallenge:       "challenge",
			TunnelerCodeChallengeMethod: "S256",
			DeviceInfo: &zdas.DeviceInfo{
				DeviceName: "laptop",
				Hostname:   "laptop.local",
				OS:         "darwin",
				Arch:       "arm64",
				OSRelease:  "25.5.0",
				OSVersion:  "26.5",
			},
			FallbackNonce:        "0123456789abcdef",
			EnrollmentMethod:     "enrollToCert",
			ClientType:           "cli",
			ZDASCodeVerifier:     "verifier",
			UpstreamProviderName: "keycloak",
			BrowserBindingHash:   strings.Repeat("ab", 32),
			CreatedAt:            time.Now(),
		}
		key := newKey(t)
		if err := s.CreateSession(t.Context(), key, clone(t, want)); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		got, err := s.ConsumeSession(t.Context(), key)
		if err != nil {
			t.Fatalf("ConsumeSession: %v", err)
		}
		if got == nil {
			t.Fatal("ConsumeSession returned a miss for a fresh session")
		}
		checkCreatedAt(t, got.CreatedAt, want.CreatedAt)
		got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
		checkJSONEqual(t, got, want)
	})

	t.Run("CodeRoundTrip", func(t *testing.T) {
		s := newStore(t)
		want := &zdas.AuthCode{
			Claims: map[string]interface{}{
				"sub":                  "ext-1",
				"device_identity_name": "alice-laptop",
				"groups":               []interface{}{"a", "b"},
				"level":                float64(3),
				"nested":               map[string]interface{}{"k": "v"},
			},
			RedirectURI:         "https://tunneler/cb",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
			IsFallback:          true,
			CreatedAt:           time.Now(),
		}
		key := newKey(t)
		if err := s.CreateCode(t.Context(), key, clone(t, want)); err != nil {
			t.Fatalf("CreateCode: %v", err)
		}
		got, err := s.ConsumeCode(t.Context(), key)
		if err != nil {
			t.Fatalf("ConsumeCode: %v", err)
		}
		if got == nil {
			t.Fatal("ConsumeCode returned a miss for a fresh code")
		}
		checkCreatedAt(t, got.CreatedAt, want.CreatedAt)
		// Used is an in-memory detail outside the Store contract.
		got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
		got.Used, want.Used = false, false
		checkJSONEqual(t, got, want)
	})

	t.Run("PendingProvisionRoundTrip", func(t *testing.T) {
		s := newStore(t)
		want := &zdas.PendingProvision{
			TunnelerRedirectURI:         "https://tunneler/cb",
			TunnelerState:               "tstate",
			TunnelerCodeChallenge:       "challenge",
			TunnelerCodeChallengeMethod: "S256",
			IsFallback:                  true,
			CreatedAt:                   time.Now(),
		}
		key := newKey(t)
		if err := s.CreatePendingProvision(t.Context(), key, clone(t, want)); err != nil {
			t.Fatalf("CreatePendingProvision: %v", err)
		}
		got, err := s.ConsumePendingProvision(t.Context(), key)
		if err != nil {
			t.Fatalf("ConsumePendingProvision: %v", err)
		}
		if got == nil {
			t.Fatal("ConsumePendingProvision returned a miss for a fresh provision")
		}
		checkCreatedAt(t, got.CreatedAt, want.CreatedAt)
		got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
		checkJSONEqual(t, got, want)
	})

	for _, k := range kinds {
		t.Run(k.name+"ConsumeIsSingleUse", func(t *testing.T) {
			s := newStore(t)
			key := newKey(t)
			if err := k.create(t.Context(), s, key); err != nil {
				t.Fatalf("create: %v", err)
			}
			if found, err := k.consume(t.Context(), s, key); err != nil || !found {
				t.Fatalf("first consume = %v, %v; want entry", found, err)
			}
			if found, err := k.consume(t.Context(), s, key); err != nil || found {
				t.Errorf("second consume = %v, %v; want miss", found, err)
			}
		})

		t.Run(k.name+"UnknownKeyIsMiss", func(t *testing.T) {
			s := newStore(t)
			if found, err := k.consume(t.Context(), s, newKey(t)); err != nil || found {
				t.Errorf("consume = %v, %v; want miss", found, err)
			}
		})

		t.Run(k.name+"ConcurrentConsumeHasOneWinner", func(t *testing.T) {
			s := newStore(t)
			key := newKey(t)
			if err := k.create(t.Context(), s, key); err != nil {
				t.Fatalf("create: %v", err)
			}
			const workers = 16
			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				wins int
			)
			start := make(chan struct{})
			for range workers {
				wg.Go(func() {
					<-start
					found, err := k.consume(t.Context(), s, key)
					if err != nil {
						t.Errorf("consume: %v", err)
						return
					}
					if found {
						mu.Lock()
						wins++
						mu.Unlock()
					}
				})
			}
			close(start)
			wg.Wait()
			if wins != 1 {
				t.Errorf("%d concurrent consumes returned the entry; want exactly 1", wins)
			}
		})
	}
}

// kind drives the per-kind subtests through one kind of Store entry.
type kind struct {
	name    string
	create  func(ctx context.Context, s zdas.Store, key string) error
	consume func(ctx context.Context, s zdas.Store, key string) (found bool, err error)
}

var kinds = []kind{
	{
		name: "Session",
		create: func(ctx context.Context, s zdas.Store, key string) error {
			return s.CreateSession(ctx, key, &zdas.AuthSession{DeviceInfo: &zdas.DeviceInfo{}, CreatedAt: time.Now()})
		},
		consume: func(ctx context.Context, s zdas.Store, key string) (bool, error) {
			v, err := s.ConsumeSession(ctx, key)
			return v != nil, err
		},
	},
	{
		name: "Code",
		create: func(ctx context.Context, s zdas.Store, key string) error {
			return s.CreateCode(ctx, key, &zdas.AuthCode{CreatedAt: time.Now()})
		},
		consume: func(ctx context.Context, s zdas.Store, key string) (bool, error) {
			v, err := s.ConsumeCode(ctx, key)
			return v != nil, err
		},
	},
	{
		name: "PendingProvision",
		create: func(ctx context.Context, s zdas.Store, key string) error {
			return s.CreatePendingProvision(ctx, key, &zdas.PendingProvision{CreatedAt: time.Now()})
		},
		consume: func(ctx context.Context, s zdas.Store, key string) (bool, error) {
			v, err := s.ConsumePendingProvision(ctx, key)
			return v != nil, err
		},
	},
}

// newKey returns a key shaped like the ones zdas passes to a Store: 64
// lowercase hex characters.
func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(b)
}

// clone returns a deep copy of v so a store that keeps the pointer it was
// given cannot make a broken round trip look correct.
func clone[T any](t *testing.T, v *T) *T {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := new(T)
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// checkCreatedAt allows for a store that truncates timestamps to its own
// precision.
func checkCreatedAt(t *testing.T, got, want time.Time) {
	t.Helper()
	if d := got.Sub(want); d < -time.Second || d > time.Second {
		t.Errorf("CreatedAt = %v, want %v (within 1s)", got, want)
	}
}

// checkJSONEqual compares by JSON encoding, which is the representation a
// store is required to preserve.
func checkJSONEqual(t *testing.T, got, want any) {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	if string(g) != string(w) {
		t.Errorf("round trip mismatch:\n got  %s\n want %s", g, w)
	}
}
