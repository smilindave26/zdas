package zdas

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllowsWithinLimit(t *testing.T) {
	rl := newIPRateLimiter(10, 10)
	for i := 0; i < 10; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
}

func TestRateLimiterBlocksOverBurst(t *testing.T) {
	rl := newIPRateLimiter(1, 2)
	rl.allow("1.2.3.4") // 1 of 2
	rl.allow("1.2.3.4") // 2 of 2
	if rl.allow("1.2.3.4") {
		t.Error("third request should be blocked (burst=2)")
	}
}

func TestRateLimiterPerIP(t *testing.T) {
	rl := newIPRateLimiter(1, 1)
	if !rl.allow("1.1.1.1") {
		t.Error("first IP should be allowed")
	}
	if !rl.allow("2.2.2.2") {
		t.Error("second IP should be allowed (separate bucket)")
	}
	if rl.allow("1.1.1.1") {
		t.Error("first IP should be blocked (burst exhausted)")
	}
}

func TestRateLimiterDisabledByDefault(t *testing.T) {
	// Config with zero rate limit - handler should not rate limit.
	h, _ := setupHandlers(t)
	mux := h.Mux()
	_, challenge := generateTestPKCE(t)

	for i := 0; i < 50; i++ {
		reqURL := "/authorize?redirect_uri=https://tunneler/cb&response_type=code&state=s1" +
			"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"
		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		req.RemoteAddr = "1.2.3.4:12345"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d got 429, but rate limiting should be disabled", i)
		}
	}
}

func TestRateLimiterEnabled(t *testing.T) {
	ks, _ := GenerateKeySet()
	reg := NewProviderRegistry()
	_ = reg.Register(&stubProvider{name: "test-idp", issuer: "https://test-idp"})
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)

	cfg := Config{
		ExternalURL: "https://zdas.example.com",
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: "https://zdas.example.com", Audience: "ziti-enroll", Expiry: 5 * time.Minute},
		RateLimit:   RateLimitConfig{AuthorizePerSecond: 1, AuthorizeBurst: 2},
	}
	h := NewHandlers(cfg, ks, reg, store, nil, nil, nil, slog.Default())
	mux := h.Mux()

	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?redirect_uri=https://tunneler/cb&response_type=code&state=s1" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&device_name=laptop"

	// First two requests should succeed (burst=2).
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		req.RemoteAddr = "1.2.3.4:12345"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should be allowed (within burst)", i)
		}
	}

	// Third request should be rate limited.
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("third request: status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 response missing Retry-After header")
	}

	// Different IP should still be allowed.
	req = httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.RemoteAddr = "5.6.7.8:12345"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code == http.StatusTooManyRequests {
		t.Error("different IP should not be rate limited")
	}
}

func TestExtractIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"basic", "1.2.3.4:1234", "", "1.2.3.4"},
		{"ipv6", "[::1]:1234", "", "::1"},
		{"xff single", "10.0.0.1:1234", "1.2.3.4", "1.2.3.4"},
		{"xff multiple", "10.0.0.1:1234", "1.2.3.4, 10.0.0.2", "1.2.3.4"},
		{"no port", "1.2.3.4", "", "1.2.3.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := extractIP(r); got != tc.want {
				t.Errorf("extractIP = %q, want %q", got, tc.want)
			}
		})
	}
}
