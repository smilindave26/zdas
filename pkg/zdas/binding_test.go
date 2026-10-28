package zdas

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// browserRequest returns a GET for target carrying the cookies prev set, as
// the browser that received prev would send them.
func browserRequest(prev *httptest.ResponseRecorder, target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range prev.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// bindingHandlers returns a mux for a deployment mounted at externalURL with
// a provider whose callback always succeeds.
func bindingHandlers(t *testing.T, externalURL string) http.Handler {
	t.Helper()
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	reg := NewProviderRegistry()
	if err := reg.Register(&callbackProvider{
		name:     "mock-idp",
		issuer:   "https://mock-idp",
		identity: &UpstreamIdentity{Subject: "u1", Username: "jsmith", Issuer: "https://mock-idp"},
	}); err != nil {
		t.Fatal(err)
	}
	store := NewSessionStore(10*time.Minute, 60*time.Second)
	t.Cleanup(store.Stop)
	cfg := Config{
		ExternalURL: externalURL,
		Claims:      defaultClaimsConfig(),
		Token:       TokenConfig{Issuer: externalURL, Audience: "ziti-enrolltocert", Expiry: 5 * time.Minute},
	}
	return NewHandlers(cfg, ks, reg, store, nil, nil, nil, slog.Default()).Mux()
}

// startAuthorize runs /authorize and returns its response and the session
// ID it sent to the IdP.
func startAuthorize(t *testing.T, mux http.Handler) (*httptest.ResponseRecorder, string) {
	t.Helper()
	_, challenge := generateTestPKCE(t)
	reqURL := "/authorize?" + url.Values{
		"redirect_uri":          {"http://localhost:20314/auth/callback"},
		"response_type":         {"code"},
		"state":                 {"tstate"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"device_name":           {"laptop"},
	}.Encode()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, reqURL, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status = %d, body = %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return w, loc.Query().Get("state")
}

func TestAuthorizeSetsBindingCookie(t *testing.T) {
	cases := []struct {
		externalURL string
		wantPath    string
		wantSecure  bool
	}{
		{"https://zdas.example.com", "/", true},
		{"https://app.example.com/enroll", "/enroll", true},
		{"http://localhost:8080", "/", false},
	}
	for _, tc := range cases {
		t.Run(tc.externalURL, func(t *testing.T) {
			w, sessID := startAuthorize(t, bindingHandlers(t, tc.externalURL))
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("got %d cookies, want 1", len(cookies))
			}
			c := cookies[0]
			if want := "zdas_bind_" + sessID[:8]; c.Name != want {
				t.Errorf("Name = %q, want %q", c.Name, want)
			}
			if !validID(c.Value) || c.Value == sessID {
				t.Errorf("Value = %q, want a 32-char hex nonce distinct from the session ID", c.Value)
			}
			if c.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", c.Path, tc.wantPath)
			}
			if c.Secure != tc.wantSecure {
				t.Errorf("Secure = %v, want %v", c.Secure, tc.wantSecure)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly not set")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", c.SameSite)
			}
			if c.MaxAge != int((10 * time.Minute).Seconds()) {
				t.Errorf("MaxAge = %d, want session timeout", c.MaxAge)
			}
		})
	}
}

func TestCallbackRequiresBindingCookie(t *testing.T) {
	cases := []struct {
		name   string
		cookie func(started *httptest.ResponseRecorder, sessID string, other *http.Cookie) *http.Cookie
		want   int
	}{
		{"matching cookie", func(started *httptest.ResponseRecorder, _ string, _ *http.Cookie) *http.Cookie {
			return started.Result().Cookies()[0]
		}, http.StatusFound},
		{"no cookie", func(*httptest.ResponseRecorder, string, *http.Cookie) *http.Cookie {
			return nil
		}, http.StatusForbidden},
		{"wrong value", func(_ *httptest.ResponseRecorder, sessID string, _ *http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindingCookieName(sessID), Value: strings.Repeat("0", 32)}
		}, http.StatusForbidden},
		{"another session's cookie", func(_ *httptest.ResponseRecorder, _ string, other *http.Cookie) *http.Cookie {
			return other
		}, http.StatusForbidden},
		{"another session's nonce under this name", func(_ *httptest.ResponseRecorder, sessID string, other *http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindingCookieName(sessID), Value: other.Value}
		}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := bindingHandlers(t, "https://zdas.example.com")
			started, sessID := startAuthorize(t, mux)
			// An attacker can start their own flow and hold its cookie.
			attacker, _ := startAuthorize(t, mux)

			req := httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+sessID, nil)
			if c := tc.cookie(started, sessID, attacker.Result().Cookies()[0]); c != nil {
				req.AddCookie(c)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d, body = %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusFound && !strings.HasPrefix(w.Header().Get("Location"), "http://localhost:20314/auth/callback?") {
				t.Errorf("Location = %q, want the tunneler callback", w.Header().Get("Location"))
			}
			// The session is spent either way, so its cookie is expired.
			cleared := false
			for _, c := range w.Result().Cookies() {
				if c.Name == bindingCookieName(sessID) && c.MaxAge < 0 {
					cleared = true
				}
			}
			if !cleared {
				t.Error("binding cookie not expired")
			}
		})
	}
}

func TestBindingCookieScope(t *testing.T) {
	cases := []struct {
		externalURL string
		wantPath    string
		wantSecure  bool
	}{
		{"https://zdas.example.com", "/", true},
		{"https://zdas.example.com/", "/", true},
		{"https://app.example.com/enroll", "/enroll", true},
		{"http://localhost:8080/a/b", "/a/b", false},
		{"", "/", false},
		{"://bad", "/", false},
	}
	for _, tc := range cases {
		path, secure := bindingCookieScope(tc.externalURL)
		if path != tc.wantPath || secure != tc.wantSecure {
			t.Errorf("bindingCookieScope(%q) = %q, %v; want %q, %v", tc.externalURL, path, secure, tc.wantPath, tc.wantSecure)
		}
	}
}
