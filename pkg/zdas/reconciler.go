package zdas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Reconciler renames identities enrolled via the fallback path (unmodified
// tunnelers that didn't send device_name). After the tunneler connects and
// reports envInfo (including hostname), the reconciler renames the identity
// from its temporary name to the final name based on the hostname.
type Reconciler struct {
	cfg       FallbackConfig
	claimsCfg ClaimsConfig
	client    *http.Client
	apiURL    string
	logger    *slog.Logger

	mu      sync.Mutex
	pending map[string]*PendingReconciliation

	// Session token for the management API (zt-session).
	sessionToken   string
	sessionExpires time.Time

	cancel  context.CancelFunc
	stopped chan struct{}
}

// PendingReconciliation tracks a fallback-enrolled identity awaiting
// reconciliation.
type PendingReconciliation struct {
	ExternalID string
	Username   string
	Nonce      string
	TrackedAt  time.Time
}

// NewReconciler creates a Reconciler. Call Start to begin background polling.
func NewReconciler(cfg FallbackConfig, claimsCfg ClaimsConfig, client *http.Client, apiURL string, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		cfg:       cfg,
		claimsCfg: claimsCfg,
		client:    client,
		apiURL:    strings.TrimSuffix(apiURL, "/"),
		logger:    logger,
		pending:   make(map[string]*PendingReconciliation),
	}
}

// Track adds a fallback-enrolled identity to the reconciliation queue.
func (r *Reconciler) Track(externalID, username, nonce string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending[externalID] = &PendingReconciliation{
		ExternalID: externalID,
		Username:   username,
		Nonce:      nonce,
		TrackedAt:  time.Now(),
	}
	r.logger.Info("tracking fallback identity for reconciliation", "external_id", externalID, "username", username)
}

// Start authenticates with the controller and begins the background polling
// loop. The initial authentication failure is non-fatal (logged as warning)
// since the reconciler can retry on each poll cycle.
func (r *Reconciler) Start(ctx context.Context) {
	if err := r.refreshSession(ctx); err != nil {
		r.logger.Warn("initial reconciler authentication failed, will retry", "error", err)
	}

	pollCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.stopped = make(chan struct{})
	go r.loop(pollCtx)
}

// Stop cancels the background poll loop and waits for it to exit.
func (r *Reconciler) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	if r.stopped != nil {
		<-r.stopped
	}
}

// PendingCount returns the number of identities awaiting reconciliation.
func (r *Reconciler) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *Reconciler) loop(ctx context.Context) {
	defer close(r.stopped)
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.poll(ctx)
		}
	}
}

func (r *Reconciler) poll(ctx context.Context) {
	r.mu.Lock()
	// Snapshot the pending list so we can release the lock during API calls.
	snapshot := make([]*PendingReconciliation, 0, len(r.pending))
	for _, p := range r.pending {
		snapshot = append(snapshot, p)
	}
	r.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	// Ensure we have a valid session.
	if time.Now().Add(5 * time.Minute).After(r.sessionExpires) {
		if err := r.refreshSession(ctx); err != nil {
			r.logger.Warn("reconciler session refresh failed", "error", err)
			return
		}
	}

	for _, p := range snapshot {
		if time.Since(p.TrackedAt) > r.cfg.Timeout {
			r.logger.Warn("fallback identity reconciliation timed out",
				"external_id", p.ExternalID, "username", p.Username,
				"tracked_for", time.Since(p.TrackedAt).Round(time.Second))
			r.mu.Lock()
			delete(r.pending, p.ExternalID)
			r.mu.Unlock()
			continue
		}

		done, err := r.reconcileOne(ctx, p)
		if err != nil {
			r.logger.Warn("reconcile failed", "external_id", p.ExternalID, "error", err)
			continue
		}
		if done {
			r.mu.Lock()
			delete(r.pending, p.ExternalID)
			r.mu.Unlock()
		}
	}
}

func (r *Reconciler) reconcileOne(ctx context.Context, p *PendingReconciliation) (bool, error) {
	// Find the identity by externalId.
	identityID, hostname, err := r.findIdentity(ctx, p.ExternalID)
	if err != nil {
		return false, err
	}
	if identityID == "" {
		return false, nil // not enrolled yet, keep tracking
	}
	if hostname == "" {
		return false, nil // enrolled but no envInfo yet, keep tracking
	}

	// Build the final name using the hostname as the device name.
	finalName := expandTemplate(r.claimsCfg.NameTemplate, p.Username, &DeviceInfo{
		DeviceName: hostname,
		Hostname:   hostname,
	})

	if err := r.renameIdentity(ctx, identityID, finalName); err != nil {
		return false, err
	}
	r.logger.Info("reconciled fallback identity",
		"identity_id", identityID,
		"old_nonce", p.Nonce,
		"new_name", finalName)
	return true, nil
}

// findIdentity queries the management API for an identity by externalId.
// Returns the identity ID and envInfo hostname, or empty strings if not found.
func (r *Reconciler) findIdentity(ctx context.Context, externalID string) (id, hostname string, err error) {
	filter := fmt.Sprintf(`externalId="%s"`, externalID)
	reqURL := r.apiURL + "/edge/management/v1/identities?filter=" + url.QueryEscape(filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("build identity request: %w", err)
	}
	req.Header.Set("zt-session", r.sessionToken)
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch identity: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read identity response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("identity query returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Data []struct {
			ID      string `json:"id"`
			EnvInfo *struct {
				Hostname string `json:"hostname"`
			} `json:"envInfo"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("parse identity response: %w", err)
	}
	if len(result.Data) == 0 {
		return "", "", nil
	}
	entry := result.Data[0]
	hn := ""
	if entry.EnvInfo != nil {
		hn = entry.EnvInfo.Hostname
	}
	return entry.ID, hn, nil
}

// renameIdentity patches the identity name via the management API.
func (r *Reconciler) renameIdentity(ctx context.Context, identityID, newName string) error {
	patchURL := r.apiURL + "/edge/management/v1/identities/" + identityID
	payload, _ := json.Marshal(map[string]string{"name": newName})

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, patchURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build patch request: %w", err)
	}
	req.Header.Set("zt-session", r.sessionToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("patch identity: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("patch identity returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (r *Reconciler) refreshSession(ctx context.Context) error {
	session, err := authenticateSession(r.client, r.apiURL)
	if err != nil {
		return err
	}
	r.sessionToken = session.Token
	r.sessionExpires = session.ExpiresAt
	r.logger.Debug("reconciler session refreshed", "expires_at", session.ExpiresAt)
	return nil
}
