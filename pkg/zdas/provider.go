package zdas

import (
	"context"
	"fmt"
	"sync"
)

// UpstreamProvider abstracts the differences between OIDC and non-OIDC upstreams.
// Handlers call AuthorizeURL to get a redirect, then ExchangeAndIdentify on
// callback.
type UpstreamProvider interface {
	// Name returns the provider name used for idp parameter matching.
	Name() string

	// Issuer returns a stable identifier for this provider (OIDC issuer URL,
	// or "https://github.com" for GitHub, etc.).
	Issuer() string

	// AuthorizeURL builds the URL to redirect the user's browser to.
	// state is ZDAS's session-encoded state. redirectURI is ZDAS's callback URL.
	AuthorizeURL(state, redirectURI string) string

	// ExchangeAndIdentify exchanges the callback code for user identity.
	// For OIDC: exchanges code for tokens, validates ID token, extracts claims.
	// For GitHub: exchanges code for access token, calls /user API, maps fields.
	ExchangeAndIdentify(ctx context.Context, code, redirectURI string) (*UpstreamIdentity, error)
}

// UpstreamIdentity is the normalized user identity from any upstream provider.
type UpstreamIdentity struct {
	Subject  string                 // unique user ID (OIDC sub, GitHub numeric ID, etc.)
	Username string                 // human-readable username (preferred_username, GitHub login, etc.)
	Issuer   string                 // where this identity came from
	Raw      map[string]interface{} // all upstream claims/fields for debugging or future use
}

// ProviderRegistry is a concurrency-safe directory of available upstream
// providers, keyed by name. Both OIDC providers (discovered from the Ziti
// controller) and directly-configured providers (GitHub, etc.) are merged
// into the same registry.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]UpstreamProvider
}

// NewProviderRegistry returns an empty registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{providers: make(map[string]UpstreamProvider)}
}

// Register adds a provider to the registry. Returns an error if a provider
// with the same name already exists.
func (r *ProviderRegistry) Register(p UpstreamProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider name collision: %q", name)
	}
	r.providers[name] = p
	return nil
}

// Resolve looks up a provider by name or issuer. If hint is empty and exactly
// one provider is registered, it returns that provider. Otherwise an empty hint
// with multiple providers returns an error indicating the caller must specify.
func (r *ProviderRegistry) Resolve(hint string) (UpstreamProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if hint == "" {
		if len(r.providers) == 1 {
			for _, p := range r.providers {
				return p, nil
			}
		}
		if len(r.providers) == 0 {
			return nil, fmt.Errorf("no upstream providers available")
		}
		return nil, fmt.Errorf("multiple idps available, idp parameter required")
	}

	// Match by name first.
	if p, ok := r.providers[hint]; ok {
		return p, nil
	}
	// Fallback: match by issuer.
	for _, p := range r.providers {
		if p.Issuer() == hint {
			return p, nil
		}
	}
	return nil, fmt.Errorf("unknown idp: %q", hint)
}

// SetOIDCProviders atomically replaces all OIDC providers (those whose names
// don't appear in the keep set). This is used by the discovery poller when the
// controller's signer list changes.
func (r *ProviderRegistry) SetOIDCProviders(oidc []UpstreamProvider, configuredNames map[string]struct{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove old OIDC entries (anything not in configuredNames).
	for name := range r.providers {
		if _, configured := configuredNames[name]; !configured {
			delete(r.providers, name)
		}
	}
	// Add new OIDC entries, checking for collisions with configured providers.
	for _, p := range oidc {
		if _, exists := configuredNames[p.Name()]; exists {
			return fmt.Errorf("discovered oidc provider %q collides with configured provider", p.Name())
		}
		r.providers[p.Name()] = p
	}
	return nil
}

// Names returns the names of all registered providers.
func (r *ProviderRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for n := range r.providers {
		names = append(names, n)
	}
	return names
}

// Len returns the number of registered providers.
func (r *ProviderRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}
