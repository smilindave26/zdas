package zdas

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	cfg         Config
	keys        *KeySet
	registry    *ProviderRegistry
	store       *SessionStore
	discovery   *Discovery            // for cached network JWTs; may be nil in tests
	reconciler  *Reconciler           // nil when fallback is disabled
	provisioner EnrollmentProvisioner // nil uses built-in ComposeClaims
	rateLimiter *ipRateLimiter        // nil when rate limiting is disabled
	logger      *slog.Logger
}

// NewHandlers creates a Handlers with the given dependencies. discovery,
// reconciler, and provisioner may be nil.
func NewHandlers(cfg Config, keys *KeySet, registry *ProviderRegistry, store *SessionStore, discovery *Discovery, reconciler *Reconciler, provisioner EnrollmentProvisioner, logger *slog.Logger) *Handlers {
	h := &Handlers{
		cfg:         cfg,
		keys:        keys,
		registry:    registry,
		store:       store,
		discovery:   discovery,
		reconciler:  reconciler,
		provisioner: provisioner,
		logger:      logger,
	}
	if cfg.RateLimit.AuthorizePerSecond > 0 {
		burst := cfg.RateLimit.AuthorizeBurst
		if burst == 0 {
			burst = int(cfg.RateLimit.AuthorizePerSecond) * 2
			if burst < 1 {
				burst = 1
			}
		}
		h.rateLimiter = newIPRateLimiter(cfg.RateLimit.AuthorizePerSecond, burst)
	}
	return h
}

// Mux returns an http.ServeMux wired to all ZDAS endpoints.
func (h *Handlers) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", h.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /network-jwts", h.handleNetworkJWTs)
	mux.HandleFunc("GET /authorize", h.handleAuthorize)
	mux.HandleFunc("GET /callback", h.handleCallback)
	mux.HandleFunc("POST /token", h.handleToken)
	mux.HandleFunc("POST /provision/complete", h.handleProvisionComplete)
	return mux
}

func (h *Handlers) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	ext := h.cfg.ExternalURL
	doc := map[string]interface{}{
		"issuer":                                ext,
		"authorization_endpoint":                ext + "/authorize",
		"token_endpoint":                        ext + "/token",
		"jwks_uri":                              ext + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"grant_types_supported":                 []string{"authorization_code"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (h *Handlers) handleNetworkJWTs(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	body := h.discovery.NetworkJWTsBody()
	if body == nil {
		http.Error(w, "network JWTs not yet available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
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
	if h.rateLimiter != nil && !h.rateLimiter.allow(extractIP(r)) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

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
	if len(h.cfg.AllowedRedirectURIs) > 0 {
		allowed := false
		for _, prefix := range h.cfg.AllowedRedirectURIs {
			if strings.HasPrefix(redirectURI, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "redirect_uri is not in the allowed list", http.StatusBadRequest)
			return
		}
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
			Hostname:   truncateParam(hostname, 255),
			OS:         truncateParam(osName, 64),
			Arch:       truncateParam(arch, 64),
			OSRelease:  truncateParam(osRelease, 128),
			OSVersion:  truncateParam(osVersion, 128),
		}
	}

	// Resolve upstream provider.
	provider, err := h.registry.Resolve(idpHint)
	if err != nil {
		switch {
		case errors.Is(err, ErrMultipleProviders):
			if h.cfg.IDPSelectorURL != "" {
				h.redirectToIDPSelector(w, r)
				return
			}
			h.renderIDPSelector(w, r)
		case errors.Is(err, ErrNoProviders):
			h.logger.Error("no upstream providers configured")
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "no upstream providers available")
		default:
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
		oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, errParam, sanitizeErrorDescription(desc))
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

	var claims map[string]interface{}
	if h.provisioner != nil {
		req := ProvisionRequest{
			Email:         identity.Email,
			Name:          identity.Username,
			Subject:       identity.Subject,
			Provider:      sess.UpstreamProviderName,
			IsFallback:    sess.FallbackNonce != "",
			FallbackNonce: sess.FallbackNonce,
		}
		if sess.DeviceInfo != nil {
			req.DeviceName = sess.DeviceInfo.DeviceName
			req.Hostname = sess.DeviceInfo.Hostname
			req.OS = sess.DeviceInfo.OS
			req.Arch = sess.DeviceInfo.Arch
			req.OSRelease = sess.DeviceInfo.OSRelease
			req.OSVersion = sess.DeviceInfo.OSVersion
		}
		result, err := h.provisioner.Provision(r.Context(), req)
		if err != nil {
			h.handleProvisionerError(w, r, err, sess.TunnelerRedirectURI, sess.TunnelerState, sess.UpstreamProviderName)
			return
		}
		if result.RedirectURL != "" && result.Claims == nil {
			// Interactive provisioning - stash session state and redirect.
			pendingID, err := h.store.CreatePendingProvision(&PendingProvision{
				TunnelerRedirectURI:         sess.TunnelerRedirectURI,
				TunnelerState:               sess.TunnelerState,
				TunnelerCodeChallenge:       sess.TunnelerCodeChallenge,
				TunnelerCodeChallengeMethod: sess.TunnelerCodeChallengeMethod,
				IsFallback:                  sess.FallbackNonce != "",
			})
			if err != nil {
				h.logger.Error("create pending provision", "error", err)
				oidcErrorRedirect(w, r, sess.TunnelerRedirectURI, sess.TunnelerState, "server_error", "internal error")
				return
			}
			sep := "?"
			if strings.Contains(result.RedirectURL, "?") {
				sep = "&"
			}
			http.Redirect(w, r, result.RedirectURL+sep+"pending_id="+pendingID, http.StatusFound)
			return
		}
		claims = result.Claims
	} else {
		claims = ComposeClaims(h.cfg.Claims, h.cfg.Fallback, identity, sess.DeviceInfo, sess.FallbackNonce)
	}

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

// sanitizeErrorDescription enforces RFC 6749 section 4.1.2.1 character class
// for OIDC error_description: printable ASCII excluding " and \, with newlines
// and other control characters replaced by spaces. Truncates to 200 chars to
// keep redirect URLs reasonable.
func sanitizeErrorDescription(s string) string {
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Allowed: %x20-21, %x23-5B, %x5D-7E (RFC 6749 §4.1.2.1).
		switch {
		case c == 0x20 || c == 0x21,
			c >= 0x23 && c <= 0x5B,
			c >= 0x5D && c <= 0x7E:
			out = append(out, c)
		default:
			out = append(out, ' ')
		}
	}
	return string(out)
}

// truncateParam caps a tunneler-supplied query parameter to maxLen bytes.
func truncateParam(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// handleProvisionerError translates an error from the EnrollmentProvisioner
// into an OIDC error redirect. A *ProvisionError with a valid OIDC code is
// passed through to the tunneler. Anything else (plain error or invalid code)
// becomes server_error with a generic description.
func (h *Handlers) handleProvisionerError(w http.ResponseWriter, r *http.Request, err error, redirectURI, state, providerName string) {
	var pe *ProvisionError
	if errors.As(err, &pe) {
		if !isValidProvisionErrorCode(pe.Code) {
			h.logger.Warn("provisioner returned invalid error code, falling back to server_error",
				"code", pe.Code, "provider", providerName)
			oidcErrorRedirect(w, r, redirectURI, state, "server_error", "provisioning failed")
			return
		}
		h.logger.Info("provisioner rejected request",
			"code", pe.Code,
			"description", pe.Description,
			"provider", providerName,
		)
		oidcErrorRedirect(w, r, redirectURI, state, pe.Code, sanitizeErrorDescription(pe.Description))
		return
	}
	h.logger.Error("provisioner failed", "error", err, "provider", providerName)
	oidcErrorRedirect(w, r, redirectURI, state, "server_error", "provisioning failed")
}

// provisionCompleteError mirrors ProvisionError as a JSON-tagged value type
// for the /provision/complete request body.
type provisionCompleteError struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

// provisionCompleteBody is the JSON body accepted by /provision/complete.
// Exactly one of Claims or Error must be set. Setting Claims completes the
// flow successfully and mints an enrollment code. Setting Error performs an
// OIDC error redirect to the tunneler instead.
//
// PendingID may optionally be included in the body instead of the query
// string. Body takes precedence over query. Embedding apps that want to
// avoid leaking the pending_id in Referer headers and logs should prefer
// the body field.
type provisionCompleteBody struct {
	PendingID string                  `json:"pending_id,omitempty"`
	Claims    map[string]any          `json:"claims,omitempty"`
	Error     *provisionCompleteError `json:"error,omitempty"`
}

// handleProvisionComplete resumes the flow after an interactive provisioning
// detour. The embedding application's picker page calls this with the pending
// ID and either the final claims (success) or a structured error (rejection).
// Either way, the pending provision is consumed and the browser is redirected
// back to the tunneler.
func (h *Handlers) handleProvisionComplete(w http.ResponseWriter, r *http.Request) {
	// Decode and validate the body BEFORE consuming the pending provision,
	// so a malformed request doesn't burn the pending state and force the
	// user to restart the entire enrollment flow.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var body provisionCompleteBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// pending_id may come from the body (preferred, avoids Referer/log
	// leakage) or the query string (backward compatible).
	pendingID := body.PendingID
	if pendingID == "" {
		pendingID = r.URL.Query().Get("pending_id")
	}
	if pendingID == "" {
		http.Error(w, "pending_id is required (in body or query)", http.StatusBadRequest)
		return
	}

	if body.Claims == nil && body.Error == nil {
		http.Error(w, `provision complete body must contain either "claims" or "error"`, http.StatusBadRequest)
		return
	}
	if body.Claims != nil && body.Error != nil {
		h.logger.Warn("provision complete: both claims and error set, preferring error",
			"pending_id", pendingID)
		body.Claims = nil
	}

	pp := h.store.ConsumePendingProvision(pendingID)
	if pp == nil {
		http.Error(w, "pending provision not found or expired", http.StatusBadRequest)
		return
	}

	if body.Error != nil {
		code := body.Error.Code
		desc := body.Error.Description
		if !isValidProvisionErrorCode(code) {
			h.logger.Warn("provision complete: invalid error code from embedding app, falling back to server_error",
				"code", code)
			code = "server_error"
			desc = "provisioning failed"
		}
		h.logger.Info("provision complete: provisioner rejected after picker",
			"code", code,
			"description", desc)
		oidcErrorRedirect(w, r, pp.TunnelerRedirectURI, pp.TunnelerState, code, sanitizeErrorDescription(desc))
		return
	}

	ac := &AuthCode{
		Claims:              body.Claims,
		RedirectURI:         pp.TunnelerRedirectURI,
		CodeChallenge:       pp.TunnelerCodeChallenge,
		CodeChallengeMethod: pp.TunnelerCodeChallengeMethod,
		IsFallback:          pp.IsFallback,
	}
	zdasCode, err := h.store.CreateCode(ac)
	if err != nil {
		h.logger.Error("create auth code from provision", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redir := pp.TunnelerRedirectURI + "?" + url.Values{
		"code":  {zdasCode},
		"state": {pp.TunnelerState},
	}.Encode()
	http.Redirect(w, r, redir, http.StatusFound)
}

// verifyPKCE validates the code_verifier against the stored code_challenge
// using the S256 method. Uses constant-time comparison to avoid timing leaks.
func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" || verifier == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
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

// redirectToIDPSelector hands picker rendering off to the embedding
// application via cfg.IDPSelectorURL. It preserves the original /authorize
// query string so the host app can echo it back to /authorize with an idp=
// parameter added, and appends a `providers` query param listing the
// available IdP names so the host app does not need to query ZDAS to know
// what to render.
func (h *Handlers) redirectToIDPSelector(w http.ResponseWriter, r *http.Request) {
	names := h.registry.Names()
	sort.Strings(names)

	// Copy the original query string verbatim and add a providers list. We
	// intentionally do NOT remove any existing params; the host app will
	// round-trip them back to /authorize unchanged so that the
	// tunneler-supplied state, PKCE, redirect_uri, device info, etc. are
	// preserved through the picker round trip.
	q := r.URL.Query()
	q.Set("providers", strings.Join(names, ","))

	target := h.cfg.IDPSelectorURL
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	redirURL := target + sep + q.Encode()

	h.logger.Info("redirecting to host app idp selector",
		"url", h.cfg.IDPSelectorURL,
		"providers", names,
	)
	http.Redirect(w, r, redirURL, http.StatusFound)
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
		// Relative URL: the browser resolves "?..." against the current
		// page (/authorize), keeping the path and replacing only the
		// query. This works regardless of how the embedding application
		// mounts ZDAS (e.g., at /zdas via http.StripPrefix).
		href := "?" + q.Encode()
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
