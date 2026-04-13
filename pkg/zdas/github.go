package zdas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	gitHubIssuer   = "https://github.com"
	gitHubAuthURL  = "https://github.com/login/oauth/authorize"
	gitHubTokenURL = "https://github.com/login/oauth/access_token"
	gitHubUserURL  = "https://api.github.com/user"
	gitHubOrgsURL  = "https://api.github.com/user/orgs"
)

// GitHubProvider is an UpstreamProvider for GitHub's OAuth 2.0 flow. GitHub
// issues opaque access tokens (not JWTs), so it cannot be registered as a Ziti
// ext-jwt-signer and must be configured directly in ZDAS.
type GitHubProvider struct {
	name          string
	clientID      string
	clientSecret  string
	usernameField string
	userIDField   string
	allowedOrgs   []string

	// Overridable for tests.
	authBaseURL  string
	tokenBaseURL string
	apiBaseURL   string
}

// NewGitHubProvider creates a GitHubProvider from the given config.
func NewGitHubProvider(cfg ProviderConfig) *GitHubProvider {
	return &GitHubProvider{
		name:          cfg.Name,
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		usernameField: cfg.UsernameField,
		userIDField:   cfg.UserIDField,
		allowedOrgs:   cfg.AllowedOrgs,
		authBaseURL:   gitHubAuthURL,
		tokenBaseURL:  gitHubTokenURL,
		apiBaseURL:    gitHubUserURL,
	}
}

func (p *GitHubProvider) Name() string   { return p.name }
func (p *GitHubProvider) Issuer() string { return gitHubIssuer }

func (p *GitHubProvider) AuthorizeURL(state, redirectURI string) string {
	v := url.Values{
		"client_id":    {p.clientID},
		"redirect_uri": {redirectURI},
		"state":        {state},
		"scope":        {"read:user user:email read:org"},
	}
	return p.authBaseURL + "?" + v.Encode()
}

func (p *GitHubProvider) ExchangeAndIdentify(ctx context.Context, code, redirectURI string) (*UpstreamIdentity, error) {
	accessToken, err := p.exchangeCode(ctx, code, redirectURI)
	if err != nil {
		return nil, err
	}
	user, err := p.fetchUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if len(p.allowedOrgs) > 0 {
		if err := p.checkOrgs(ctx, accessToken); err != nil {
			return nil, err
		}
	}

	subject := extractField(user, p.userIDField)
	username := extractField(user, p.usernameField)

	// Always fetch /user/emails and use the primary verified address. The
	// /user endpoint's "email" field may be an unverified public email, so
	// we don't trust it even when present.
	email := p.fetchPrimaryEmail(ctx, accessToken)

	return &UpstreamIdentity{
		Subject:  subject,
		Email:    email,
		Username: username,
		Issuer:   gitHubIssuer,
		Raw:      user,
	}, nil
}

func (p *GitHubProvider) exchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenBaseURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("build github token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return "", fmt.Errorf("read github token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse github token response: %w", err)
	}
	if errMsg, ok := result["error"].(string); ok {
		desc, _ := result["error_description"].(string)
		return "", fmt.Errorf("github token error: %s: %s", errMsg, desc)
	}
	token, ok := result["access_token"].(string)
	if !ok || token == "" {
		return "", fmt.Errorf("no access_token in github response")
	}
	return token, nil
}

func (p *GitHubProvider) fetchUser(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build github user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github user request: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read github user response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user api returned %d: %s", resp.StatusCode, body)
	}

	var user map[string]interface{}
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("parse github user response: %w", err)
	}
	return user, nil
}

func (p *GitHubProvider) checkOrgs(ctx context.Context, accessToken string) error {
	orgsURL := strings.TrimSuffix(p.apiBaseURL, "/") + "/orgs"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, orgsURL, nil)
	if err != nil {
		return fmt.Errorf("build github orgs request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("github orgs request: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return fmt.Errorf("read github orgs response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github orgs api returned %d: %s", resp.StatusCode, body)
	}

	var orgs []map[string]interface{}
	if err := json.Unmarshal(body, &orgs); err != nil {
		return fmt.Errorf("parse github orgs response: %w", err)
	}

	allowed := make(map[string]struct{}, len(p.allowedOrgs))
	for _, o := range p.allowedOrgs {
		allowed[o] = struct{}{}
	}
	for _, org := range orgs {
		login, _ := org["login"].(string)
		if _, ok := allowed[login]; ok {
			return nil
		}
	}
	return fmt.Errorf("user not in allowed organization")
}

// fetchPrimaryEmail fetches the user's primary verified email from the GitHub
// /user/emails endpoint. Returns empty string on any failure (best-effort).
func (p *GitHubProvider) fetchPrimaryEmail(ctx context.Context, accessToken string) string {
	emailsURL := strings.TrimSuffix(p.apiBaseURL, "/") + "/emails"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, emailsURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return ""
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	return ""
}

// extractField extracts a string value from a JSON-decoded map. Numeric values
// (like GitHub's user ID) are converted to string.
func extractField(data map[string]interface{}, field string) string {
	v, ok := data[field]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strconv.FormatInt(int64(val), 10)
	case json.Number:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}
