package zdas

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Handlers groups the HTTP handler dependencies for the ZDAS endpoints.
type Handlers struct {
	cfg        Config
	keys       *KeySet
	registry   *ProviderRegistry
	store      *SessionStore
	reconciler *Reconciler // nil when fallback is disabled
	logger     *slog.Logger
}

// NewHandlers creates a Handlers with the given dependencies. reconciler may
// be nil when fallback is disabled.
func NewHandlers(cfg Config, keys *KeySet, registry *ProviderRegistry, store *SessionStore, reconciler *Reconciler, logger *slog.Logger) *Handlers {
	return &Handlers{
		cfg:        cfg,
		keys:       keys,
		registry:   registry,
		store:      store,
		reconciler: reconciler,
		logger:     logger,
	}
}

// Mux returns an http.ServeMux wired to all ZDAS endpoints.
func (h *Handlers) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", h.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /authorize", h.handleAuthorize)
	mux.HandleFunc("GET /callback", h.handleCallback)
	mux.HandleFunc("POST /token", h.handleToken)
	return mux
}

func (h *Handlers) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	ext := h.cfg.ExternalURL
	doc := map[string]interface{}{
		"issuer":                 ext,
		"authorization_endpoint": ext + "/authorize",
		"token_endpoint":         ext + "/token",
		"jwks_uri":               ext + "/.well-known/jwks.json",
		"response_types_supported":               []string{"code"},
		"subject_types_supported":                []string{"public"},
		"id_token_signing_alg_values_supported":  []string{"ES256"},
		"grant_types_supported":                  []string{"authorization_code"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (h *Handlers) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := h.keys.PublicJWKS()
	if err != nil {
		h.logger.Error("marshal jwks", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *Handlers) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	deviceName := q.Get("device_name")
	hostname := q.Get("hostname")
	osName := q.Get("os")
	arch := q.Get("arch")
	osRelease := q.Get("os_release")
	osVersion := q.Get("os_version")
	idpHint := q.Get("idp") // set by the IdP selector page, not by tunnelers
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// Validate redirect_uri early - before we trust it for error redirects.
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil || (parsedRedirect.Scheme != "http" && parsedRedirect.Scheme != "https") {
		http.Error(w, "redirect_uri must be a valid http(s) URL", http.StatusBadRequest)
		return
	}

	// Validate remaining required parameters.
	if codeChallenge == "" || codeChallengeMethod == "" {
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "PKCE code_challenge and code_challenge_method are required")
		return
	}
	if codeChallengeMethod != "S256" {
		oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "only S256 code_challenge_method is supported")
		return
	}
	var deviceInfo *DeviceInfo
	var fallbackNonce string
	if deviceName == "" {
		if !h.cfg.Fallback.Enabled {
			oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "device_name parameter required")
			return
		}
		// Fallback path: generate a nonce for this enrollment.
		nonce, err := generateShortNonce()
		if err != nil {
			h.logger.Error("generate fallback nonce", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
		fallbackNonce = nonce
	} else {
		if len(deviceName) > 255 {
			oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "device_name too long (max 255 characters)")
			return
		}
		deviceInfo = &DeviceInfo{
			DeviceName: deviceName,
			Hostname:   hostname,
			OS:         osName,
			Arch:       arch,
			OSRelease:  osRelease,
			OSVersion:  osVersion,
		}
	}

	// Resolve upstream provider.
	provider, err := h.registry.Resolve(idpHint)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "multiple") {
			// Show an IdP selection page so the user can choose.
			h.renderIDPSelector(w, r)
			return
		} else if strings.Contains(errMsg, "no upstream") {
			h.logger.Error("no upstream providers configured")
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "no upstream providers available")
		} else {
			oidcErrorRedirect(w, r, redirectURI, state, "invalid_request", "unknown idp")
		}
		return
	}

	// Build session and redirect to upstream.
	callbackURL := h.cfg.ExternalURL + "/callback"

	sess := &AuthSession{
		TunnelerRedirectURI:         redirectURI,
		TunnelerState:               state,
		TunnelerCodeChallenge:       codeChallenge,
		TunnelerCodeChallengeMethod: codeChallengeMethod,
		DeviceInfo:                  deviceInfo,
		FallbackNonce:               fallbackNonce,
		UpstreamProviderName:        provider.Name(),
	}

	var upstreamURL string
	if oidcProv, ok := provider.(*OIDCProvider); ok {
		// OIDC: generate our own PKCE pair for the upstream, then store the
		// verifier in the session so /callback can use it.
		verifier, challenge, err := generatePKCE()
		if err != nil {
			h.logger.Error("generate pkce", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
		sess.ZDASCodeVerifier = verifier
		sessionState, err := h.store.CreateSession(sess)
		if err != nil {
			h.logger.Error("create session", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
		v := url.Values{
			"client_id":             {oidcProv.clientID},
			"response_type":         {"code"},
			"redirect_uri":          {callbackURL},
			"state":                 {sessionState},
			"scope":                 {joinScopes(oidcProv.scopes)},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		upstreamURL = oidcProv.authURL + "?" + v.Encode()
	} else {
		// Non-OIDC (e.g. GitHub): no upstream PKCE.
		sessionState, err := h.store.CreateSession(sess)
		if err != nil {
			h.logger.Error("create session", "error", err)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "internal error")
			return
		}
		upstreamURL = provider.AuthorizeURL(sessionState, callbackURL)
	}

	if fallbackNonce != "" {
		h.logger.Info("redirecting to upstream (fallback)", "provider", provider.Name(), "nonce", fallbackNonce)
	} else {
		h.logger.Info("redirecting to upstream", "provider", provider.Name(), "device", deviceName)
	}
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

func (h *Handlers) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	sessionState := q.Get("state")

	if errParam := q.Get("error"); errParam != "" {
		desc := q.Get("error_description")
		h.logger.Warn("upstream returned error", "error", errParam, "description", desc)
		// We need the session to know the tunneler's redirect_uri.
		sess := h.store.GetSession(sessionState)
		if sess == nil {
			http.Error(w, "session not found or expired", http.StatusBadRequest)
			return
		}
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, errParam, desc)
		return
	}

	sess := h.store.GetSession(sessionState)
	if sess == nil {
		http.Error(w, "session not found or expired", http.StatusBadRequest)
		return
	}

	provider, err := h.registry.Resolve(sess.UpstreamProviderName)
	if err != nil {
		h.logger.Error("resolve provider from session", "provider", sess.UpstreamProviderName, "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "provider no longer available")
		return
	}

	callbackURL := h.cfg.ExternalURL + "/callback"
	var identity *UpstreamIdentity
	if oidcProv, ok := provider.(*OIDCProvider); ok && sess.ZDASCodeVerifier != "" {
		identity, err = oidcProv.ExchangeAndIdentifyWithPKCE(r.Context(), code, callbackURL, sess.ZDASCodeVerifier)
	} else {
		identity, err = provider.ExchangeAndIdentify(r.Context(), code, callbackURL)
	}
	if err != nil {
		h.logger.Error("exchange and identify", "provider", provider.Name(), "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "upstream authentication failed")
		return
	}

	claims := ComposeClaims(h.cfg.Claims, h.cfg.Fallback, identity, sess.DeviceInfo, sess.FallbackNonce)

	// Track fallback enrollments for reconciliation.
	if sess.FallbackNonce != "" && h.reconciler != nil {
		if extID, ok := claims[h.cfg.Claims.ExternalIDClaim].(string); ok {
			username, _ := claims["preferred_username"].(string)
			h.reconciler.Track(extID, username, sess.FallbackNonce)
		}
	}

	ac := &AuthCode{
		Claims:              claims,
		RedirectURI:         sess.TunnelerRedirectURI,
		CodeChallenge:       sess.TunnelerCodeChallenge,
		CodeChallengeMethod: sess.TunnelerCodeChallengeMethod,
		IsFallback:          sess.FallbackNonce != "",
	}
	zdasCode, err := h.store.CreateCode(ac)
	if err != nil {
		h.logger.Error("create auth code", "error", err)
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
		return
	}

	redir := sess.TunnelerRedirectURI + "?" + url.Values{
		"code":  {zdasCode},
		"state": {sess.TunnelerState},
	}.Encode()
	deviceLog := "fallback"
	if sess.DeviceInfo != nil {
		deviceLog = sess.DeviceInfo.DeviceName
	}
	h.logger.Info("callback complete, redirecting to tunneler", "provider", provider.Name(), "device", deviceLog)
	http.Redirect(w, r, redir, http.StatusFound)
}

func (h *Handlers) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "malformed form body")
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if grantType != "authorization_code" {
		tokenError(w, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	if code == "" {
		tokenError(w, "invalid_request", "code is required")
		return
	}

	ac := h.store.ConsumeCode(code)
	if ac == nil {
		tokenError(w, "invalid_grant", "code is invalid, expired, or already used")
		return
	}
	if ac.RedirectURI != redirectURI {
		tokenError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) {
		tokenError(w, "invalid_grant", "PKCE verification failed")
		return
	}

	signed, err := MintToken(h.cfg.Token, ac.Claims, h.keys)
	if err != nil {
		h.logger.Error("mint token", "error", err)
		tokenError(w, "server_error", "token signing failed")
		return
	}

	resp := map[string]interface{}{
		"access_token": signed,
		"id_token":     signed,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.Token.Expiry.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// verifyPKCE validates the code_verifier against the stored code_challenge
// using the S256 method.
func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" || verifier == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// oidcErrorRedirect sends an OIDC-compliant error redirect.
func oidcErrorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	v := url.Values{
		"error":             {errCode},
		"error_description": {errDesc},
	}
	if state != "" {
		v.Set("state", state)
	}
	http.Redirect(w, r, redirectURI+"?"+v.Encode(), http.StatusFound)
}

// tokenError writes a JSON error response for the /token endpoint.
func tokenError(w http.ResponseWriter, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}

// renderIDPSelector shows an HTML page listing available identity providers
// when multiple are configured and no selection has been made yet. Each link
// re-enters /authorize with the original query parameters plus idp=<name>,
// so all tunneler params (redirect_uri, state, PKCE, device info) carry through.
func (h *Handlers) renderIDPSelector(w http.ResponseWriter, r *http.Request) {
	names := h.registry.Names()
	sort.Strings(names)

	// Rebuild the original query without idp so we can add it per-provider.
	baseQuery := r.URL.Query()
	baseQuery.Del("idp")

	var links strings.Builder
	for _, name := range names {
		q := make(url.Values)
		for k, v := range baseQuery {
			q[k] = v
		}
		q.Set("idp", name)
		href := "/authorize?" + q.Encode()
		links.WriteString(fmt.Sprintf(
			`<a href="%s">%s</a>`,
			html.EscapeString(href),
			html.EscapeString(name),
		))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, idpSelectorHTML, links.String())
}

const idpSelectorHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Select Identity Provider</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; color: #333; }
  h1 { font-size: 1.4em; font-weight: 600; margin-bottom: 24px; }
  a { display: block; padding: 14px 20px; margin: 8px 0; background: #f5f5f5; border: 1px solid #ddd; border-radius: 8px; color: #333; text-decoration: none; font-size: 1em; }
  a:hover { background: #e8e8e8; border-color: #ccc; }
</style>
</head>
<body>
<h1>Select an identity provider</h1>
%s
</body>
</html>`
