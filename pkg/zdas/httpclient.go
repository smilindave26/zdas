package zdas

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpClient is the shared HTTP client for outbound requests (token exchanges,
// GitHub API calls, etc.) with a sensible timeout.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// maxResponseBytes is the cap on outbound response body reads. Prevents a
// compromised upstream or MITM from exhausting memory. 2 MB is generous for
// any JSON API response ZDAS consumes.
const maxResponseBytes = 2 << 20

// readResponseBody reads a response body with a size cap to prevent memory
// exhaustion from oversized upstream responses.
func readResponseBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
}

// oidcTokenExchange performs an OAuth2 token exchange POST and returns the
// parsed JSON response body. It is a package-level function variable so tests
// can replace the transport without starting real HTTP servers.
var oidcTokenExchange = defaultOIDCTokenExchange

func defaultOIDCTokenExchange(ctx context.Context, tokenURL string, params url.Values) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	return result, nil
}
