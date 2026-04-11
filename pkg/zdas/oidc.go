package zdas

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCProvider is an UpstreamProvider backed by a standard OIDC issuer. It
// can be created dynamically from ext-jwt-signers discovered on the Ziti
// controller (public client + PKCE, no secret) or configured directly with
// a client secret for IdPs that require a confidential client in the token
// exchange (e.g. Google Web application OAuth clients). PKCE is always
// applied when a verifier is threaded through the session.
type OIDCProvider struct {
	name         string
	issuer       string
	clientID     string
	clientSecret string // optional; set for confidential-client IdPs (e.g. Google Web)
	authURL      string
	tokenURL     string
	verifier     *oidc.IDTokenVerifier
	scopes       []string
}

// OIDCProviderConfig holds the data needed to construct an OIDCProvider.
// Sourced either from a discovered ext-jwt-signer (secret empty) or from
// ProviderConfig for directly-configured OIDC providers.
type OIDCProviderConfig struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string // optional; required by some IdPs (e.g. Google Web client) in the token exchange
	AuthURL      string
	TokenURL     string
	Scopes       []string
}

// NewOIDCProvider creates an OIDCProvider from the given config. It creates an
// ID token verifier bound to the provider's OIDC discovery data.
func NewOIDCProvider(ctx context.Context, cfg OIDCProviderConfig) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.Issuer, err)
	}

	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = provider.Endpoint().AuthURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = provider.Endpoint().TokenURL
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &OIDCProvider{
		name:         cfg.Name,
		issuer:       cfg.Issuer,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		authURL:      authURL,
		tokenURL:     tokenURL,
		verifier:     verifier,
		scopes:       scopes,
	}, nil
}

func (p *OIDCProvider) Name() string   { return p.name }
func (p *OIDCProvider) Issuer() string { return p.issuer }

// AuthorizeURL builds the upstream OIDC authorization URL with ZDAS's own PKCE
// challenge. The verifier must be stored in the session before calling this.
func (p *OIDCProvider) AuthorizeURL(state, redirectURI string) string {
	// Build URL manually to avoid oauth2 package's automatic params.
	v := url.Values{
		"client_id":     {p.clientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"scope":         {joinScopes(p.scopes)},
	}
	return p.authURL + "?" + v.Encode()
}

// AuthorizeURLWithPKCE is like AuthorizeURL but includes PKCE parameters.
// It returns the URL and the code verifier that must be stored in the session.
func (p *OIDCProvider) AuthorizeURLWithPKCE(state, redirectURI string) (authURL, codeVerifier string, err error) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", "", err
	}
	v := url.Values{
		"client_id":             {p.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"scope":                 {joinScopes(p.scopes)},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return p.authURL + "?" + v.Encode(), verifier, nil
}

// ExchangeAndIdentify exchanges the authorization code for tokens via the
// upstream token endpoint, validates the ID token, and returns the normalized
// identity.
func (p *OIDCProvider) ExchangeAndIdentify(ctx context.Context, code, redirectURI string) (*UpstreamIdentity, error) {
	return p.exchangeAndIdentify(ctx, code, redirectURI, "")
}

// ExchangeAndIdentifyWithPKCE is like ExchangeAndIdentify but includes the
// PKCE code_verifier in the token exchange.
func (p *OIDCProvider) ExchangeAndIdentifyWithPKCE(ctx context.Context, code, redirectURI, codeVerifier string) (*UpstreamIdentity, error) {
	return p.exchangeAndIdentify(ctx, code, redirectURI, codeVerifier)
}

func (p *OIDCProvider) exchangeAndIdentify(ctx context.Context, code, redirectURI, codeVerifier string) (*UpstreamIdentity, error) {
	params := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {p.clientID},
	}
	if p.clientSecret != "" {
		params.Set("client_secret", p.clientSecret)
	}
	if codeVerifier != "" {
		params.Set("code_verifier", codeVerifier)
	}

	tokenResp, err := oidcTokenExchange(ctx, p.tokenURL, params)
	if err != nil {
		return nil, fmt.Errorf("token exchange with %s: %w", p.name, err)
	}

	rawIDToken, ok := tokenResp["id_token"].(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("no id_token in response from %s", p.name)
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token from %s: %w", p.name, err)
	}

	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		EmailVerified     *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract claims from %s: %w", p.name, err)
	}

	raw := make(map[string]interface{})
	_ = idToken.Claims(&raw)

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Name
	}
	if username == "" {
		username = claims.Sub
	}

	// Only surface the email if the upstream IdP asserts it is verified.
	// A missing email_verified claim is treated as unverified (safe default).
	email := ""
	if claims.Email != "" {
		if claims.EmailVerified != nil && *claims.EmailVerified {
			email = claims.Email
		}
	}

	return &UpstreamIdentity{
		Subject:  claims.Sub,
		Email:    email,
		Username: username,
		Issuer:   p.issuer,
		Raw:      raw,
	}, nil
}

// joinScopes joins scopes with space separator per OAuth2 spec.
func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// generatePKCE creates a new PKCE code verifier (32 random bytes, base64url)
// and its S256 challenge.
func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate pkce verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}
