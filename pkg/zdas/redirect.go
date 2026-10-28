package zdas

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// parseRedirectURI parses raw as an absolute http(s) URL with a host and no
// userinfo. It applies to request redirect_uri values and to
// AllowedRedirectURIs entries alike.
func parseRedirectURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("scheme must be http or https")
	}
	if u.User != nil {
		return nil, errors.New("userinfo is not allowed")
	}
	if u.Hostname() == "" {
		return nil, errors.New("host is required")
	}
	return u, nil
}

// redirectAllowed reports whether a code may be sent to u, which must come
// from parseRedirectURI. With no allow list, only loopback callbacks are
// accepted (RFC 8252 section 7.3), which is all a tunneler sends. Entries
// that fail to parse never match; Config.Validate rejects them at startup.
func redirectAllowed(u *url.URL, allowList []string) bool {
	if len(allowList) == 0 {
		return isLoopbackHost(u.Hostname())
	}
	for _, raw := range allowList {
		entry, err := parseRedirectURI(raw)
		if err == nil && redirectMatches(u, entry) {
			return true
		}
	}
	return false
}

// redirectMatches compares scheme, host and port, and the path when entry
// has one. An entry for a loopback host without a port matches any port,
// since loopback callbacks listen on an ephemeral one.
func redirectMatches(u, entry *url.URL) bool {
	if u.Scheme != entry.Scheme || !strings.EqualFold(u.Hostname(), entry.Hostname()) {
		return false
	}
	if entry.Port() != "" || !isLoopbackHost(entry.Hostname()) {
		if effectivePort(u) != effectivePort(entry) {
			return false
		}
	}
	return entry.Path == "" || entry.Path == "/" || u.Path == entry.Path
}

// effectivePort returns u's port, or the default port for its scheme.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP
// literal. Shorthand and non-canonical forms ("127.1", "localhost.", hex)
// are rejected rather than resolved.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
