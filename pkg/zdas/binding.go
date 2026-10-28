package zdas

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
)

// bindingCookiePrefix names the cookie that ties an auth session to the
// browser that started it. The name ends with the first 8 characters of
// the session ID so concurrent enrollments in one browser don't collide.
const bindingCookiePrefix = "zdas_bind_"

func bindingCookieName(sessionID string) string {
	return bindingCookiePrefix + sessionID[:8]
}

func bindingHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

// bindingCookieScope returns the cookie path and Secure flag for the
// deployment at externalURL. The path is the URL's path, so the cookie
// reaches /authorize and /callback under whatever prefix zdas is mounted at.
func bindingCookieScope(externalURL string) (path string, secure bool) {
	u, err := url.Parse(externalURL)
	if err != nil || u.Path == "" {
		return "/", err == nil && u.Scheme == "https"
	}
	return u.Path, u.Scheme == "https"
}

// startSession stores sess and sets a cookie holding a nonce whose hash is
// kept in the session, so that only the browser that started the flow can
// complete it at /callback. It returns the session ID.
func (h *Handlers) startSession(w http.ResponseWriter, r *http.Request, sess *AuthSession) (string, error) {
	nonce, err := randomID()
	if err != nil {
		return "", err
	}
	sess.BrowserBindingHash = bindingHash(nonce)
	id, err := h.createSession(r.Context(), sess)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     bindingCookieName(id),
		Value:    nonce,
		Path:     h.cookiePath,
		MaxAge:   int(h.cfg.Session.Timeout.Seconds()),
		Secure:   h.cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return id, nil
}

// browserBound reports whether r carries the binding cookie for the session
// consumed under id, and expires that cookie. A session with no binding
// hash was not created by /authorize (an embedder may fill a SessionStore
// directly), so there is no browser to check against.
func (h *Handlers) browserBound(w http.ResponseWriter, r *http.Request, id string, sess *AuthSession) bool {
	if sess.BrowserBindingHash == "" {
		return true
	}
	name := bindingCookieName(id)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Path:     h.cookiePath,
		MaxAge:   -1,
		Secure:   h.cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	c, err := r.Cookie(name)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(bindingHash(c.Value)), []byte(sess.BrowserBindingHash)) == 1
}
