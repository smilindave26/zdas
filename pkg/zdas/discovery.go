package zdas

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Discovery polls the Ziti controller's public ext-jwt-signers endpoint and
// builds OIDCProvider instances from signers that have enrollment enabled
// (enrollToCertEnabled or enrollToTokenEnabled).
// It merges them into the ProviderRegistry alongside any configured providers.
type Discovery struct {
	cfg            ControllerConfig
	registry       *ProviderRegistry
	configuredNames map[string]struct{}
	client         *http.Client
	logger         *slog.Logger

	mu              sync.Mutex
	cancel          context.CancelFunc
	stopped         chan struct{}
	networkJWTsBody []byte // cached response from GET /network-jwts
}

// NewDiscovery creates a Discovery poller. configuredNames is the set of
// provider names that come from the ZDAS config (GitHub, etc.) and must not
// collide with discovered signers.
func NewDiscovery(cfg ControllerConfig, registry *ProviderRegistry, configuredNames map[string]struct{}, logger *slog.Logger) (*Discovery, error) {
	client, err := controllerClient(cfg.APIURL, cfg.IdentityFile)
	if err != nil {
		return nil, err
	}
	return &Discovery{
		cfg:             cfg,
		registry:        registry,
		configuredNames: configuredNames,
		client:          client,
		logger:          logger,
	}, nil
}

// RunOnce performs a single discovery poll. Suitable for startup.
func (d *Discovery) RunOnce(ctx context.Context) error {
	return d.poll(ctx)
}

// Start begins periodic polling at the configured PollInterval. It runs the
// first poll synchronously and returns an error if it fails. Subsequent poll
// failures are logged but non-fatal.
func (d *Discovery) Start(ctx context.Context) error {
	if err := d.poll(ctx); err != nil {
		return fmt.Errorf("initial discovery poll: %w", err)
	}
	if d.cfg.PollInterval <= 0 {
		return nil
	}

	pollCtx, cancel := context.WithCancel(ctx)
	d.mu.Lock()
	d.cancel = cancel
	d.stopped = make(chan struct{})
	d.mu.Unlock()

	go d.loop(pollCtx)
	return nil
}

// Stop cancels the background poll loop and waits for it to exit.
func (d *Discovery) Stop() {
	d.mu.Lock()
	cancel := d.cancel
	stopped := d.stopped
	d.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		<-stopped
	}
}

func (d *Discovery) loop(ctx context.Context) {
	defer close(d.stopped)
	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.poll(ctx); err != nil {
				d.logger.Warn("discovery poll failed, keeping previous providers", "error", err)
			}
		}
	}
}

// signerResponse matches the relevant fields from the controller's
// GET /edge/client/v1/external-jwt-signers response.
type signerResponse struct {
	Data []signerEntry `json:"data"`
}

type signerEntry struct {
	Name                string `json:"name"`
	Issuer              string `json:"issuer"`
	ClientID            string `json:"clientId"`
	ExternalAuthURL     string `json:"externalAuthUrl"`
	EnrollToCertEnabled bool   `json:"enrollToCertEnabled"`
	EnrollToTokenEnabled bool  `json:"enrollToTokenEnabled"`
}

// NetworkJWTsBody returns the cached response from the controller's
// /network-jwts endpoint, or nil if not yet fetched.
func (d *Discovery) NetworkJWTsBody() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.networkJWTsBody
}

func (d *Discovery) poll(ctx context.Context) error {
	signers, err := d.fetchSigners(ctx)
	if err != nil {
		return err
	}

	// Fetch network JWTs alongside signers. Failure is non-fatal - keep
	// the stale cache and log a warning.
	if body, err := d.fetchNetworkJWTs(ctx); err != nil {
		d.logger.Warn("failed to fetch network JWTs, keeping stale cache", "error", err)
	} else {
		d.mu.Lock()
		d.networkJWTsBody = body
		d.mu.Unlock()
	}

	var providers []UpstreamProvider
	for _, s := range signers {
		if !s.EnrollToCertEnabled && !s.EnrollToTokenEnabled {
			continue
		}
		// Exclude self. Match on issuer or externalAuthUrl (the public API
		// may return an empty issuer for newly created signers).
		if s.Issuer == d.cfg.SelfIssuer ||
			(s.ExternalAuthURL != "" && strings.HasPrefix(s.ExternalAuthURL, d.cfg.SelfIssuer)) {
			d.logger.Debug("excluding self from discovered signers", "name", s.Name, "issuer", s.Issuer)
			continue
		}
		if s.Issuer == "" {
			d.logger.Debug("skipping signer with empty issuer", "name", s.Name)
			continue
		}
		p, err := NewOIDCProvider(ctx, OIDCProviderConfig{
			Name:     s.Name,
			Issuer:   s.Issuer,
			ClientID: s.ClientID,
			AuthURL:  s.ExternalAuthURL,
		})
		if err != nil {
			d.logger.Warn("failed to create oidc provider from signer, skipping", "name", s.Name, "error", err)
			continue
		}
		d.logger.Info("discovered oidc provider", "name", s.Name, "issuer", s.Issuer)
		providers = append(providers, p)
	}

	if err := d.registry.SetOIDCProviders(providers, d.configuredNames); err != nil {
		return fmt.Errorf("update provider registry: %w", err)
	}
	return nil
}

func (d *Discovery) fetchSigners(ctx context.Context) ([]signerEntry, error) {
	url := d.cfg.APIURL + "/edge/client/v1/external-jwt-signers"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build signers request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signers: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read signers response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signers endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result signerResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse signers response: %w", err)
	}
	return result.Data, nil
}

// controllerClient builds an HTTP client for controller communication. When
// an identity file is provided, the CA is extracted from it. Otherwise, the CA
// is bootstrapped from the controller's /.well-known/est/cacerts endpoint
// (fetched with an insecure TLS client, then used to verify subsequent
// requests). No client certificate is presented - this is for the public API.
func controllerClient(apiURL, identityFilePath string) (*http.Client, error) {
	if identityFilePath != "" {
		id, err := loadIdentityFile(identityFilePath)
		if err != nil {
			return nil, err
		}
		return discoveryClientFromIdentity(id), nil
	}

	// No identity file - bootstrap the CA from the controller.
	pool, err := bootstrapCAPool(apiURL)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}, nil
}

func (d *Discovery) fetchNetworkJWTs(ctx context.Context) ([]byte, error) {
	reqURL := d.cfg.APIURL + "/network-jwts"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build network-jwts request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch network-jwts: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read network-jwts response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network-jwts endpoint returned %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
