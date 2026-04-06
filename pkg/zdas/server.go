package zdas

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Server is the top-level ZDAS instance. It wires together config, key
// management, provider discovery, session storage, and HTTP serving.
type Server struct {
	cfg        Config
	keys       *KeySet
	registry   *ProviderRegistry
	store      *SessionStore
	discovery  *Discovery
	reconciler *Reconciler // nil when fallback is disabled
	handlers   *Handlers
	httpSrv    *http.Server
	chalSrv    *http.Server // ACME challenge listener (if separate from main)
	logger     *slog.Logger
}

// NewServer creates a fully-wired Server. Call Start to begin serving.
func NewServer(cfg Config, logger *slog.Logger) (*Server, error) {
	keys, err := GenerateKeySet()
	if err != nil {
		return nil, fmt.Errorf("generate key set: %w", err)
	}
	logger.Info("generated signing key", "kid", keys.KID())

	registry := NewProviderRegistry()
	store := NewSessionStore(cfg.Session.Timeout, cfg.Session.CodeExpiry)

	// Register configured (non-OIDC) providers.
	configuredNames := make(map[string]struct{}, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		configuredNames[pc.Name] = struct{}{}
		switch pc.Type {
		case ProviderTypeGitHub:
			if err := registry.Register(NewGitHubProvider(pc)); err != nil {
				return nil, fmt.Errorf("register provider %q: %w", pc.Name, err)
			}
			logger.Info("registered configured provider", "name", pc.Name, "type", pc.Type)
		}
	}

	disc, err := NewDiscovery(cfg.Controller, registry, configuredNames, logger)
	if err != nil {
		return nil, fmt.Errorf("create discovery: %w", err)
	}

	var reconciler *Reconciler
	if cfg.Fallback.Enabled && cfg.Controller.IdentityFile != "" {
		id, err := loadIdentityFile(cfg.Controller.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("load identity file for reconciler: %w", err)
		}
		mgmtClient := managementClientFromIdentity(id)
		apiURL := cfg.Controller.APIURL
		if id.APIURL != "" {
			apiURL = id.APIURL
		}
		reconciler = NewReconciler(cfg.Fallback, cfg.Claims, mgmtClient, apiURL, logger)
		logger.Info("fallback reconciler enabled", "poll_interval", cfg.Fallback.PollInterval)
	}

	handlers := NewHandlers(cfg, keys, registry, store, reconciler, logger)

	return &Server{
		cfg:        cfg,
		keys:       keys,
		registry:   registry,
		store:      store,
		discovery:  disc,
		reconciler: reconciler,
		handlers:   handlers,
		logger:     logger,
	}, nil
}

// Handler wraps an http.Handler with a Stop method for clean shutdown of
// background goroutines (discovery polling, session cleanup).
type Handler struct {
	http.Handler
	srv *Server
}

// Stop halts background goroutines started by NewHandler. Call this when the
// embedding application is shutting down.
func (h *Handler) Stop() {
	h.srv.discovery.Stop()
	if h.srv.reconciler != nil {
		h.srv.reconciler.Stop()
	}
	h.srv.store.Stop()
}

// NewHandler returns a Handler for embedding ZDAS in another application.
// It performs initial discovery but does not start an HTTP server. The caller
// is responsible for serving the returned handler and calling Stop on shutdown.
func NewHandler(cfg Config, logger *slog.Logger) (*Handler, error) {
	srv, err := NewServer(cfg, logger)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if err := srv.discovery.Start(ctx); err != nil {
		return nil, fmt.Errorf("start discovery: %w", err)
	}
	if srv.reconciler != nil {
		srv.reconciler.Start(ctx)
	}
	return &Handler{Handler: srv.handlers.Mux(), srv: srv}, nil
}

// Start performs initial discovery and begins serving HTTP(S). It blocks until
// the server shuts down.
func (s *Server) Start(ctx context.Context) error {
	if err := s.discovery.Start(ctx); err != nil {
		return fmt.Errorf("start discovery: %w", err)
	}
	if s.reconciler != nil {
		s.reconciler.Start(ctx)
	}

	mux := s.handlers.Mux()
	s.httpSrv = &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info("starting zdas",
		"listen", s.cfg.Listen,
		"external_url", s.cfg.ExternalURL,
		"tls_mode", s.cfg.TLS.Mode,
		"providers", s.registry.Len(),
	)

	switch s.cfg.TLS.Mode {
	case TLSModeNone:
		return s.httpSrv.ListenAndServe()
	case TLSModeStatic:
		return s.httpSrv.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	case TLSModeACME:
		return s.listenACME()
	default:
		return fmt.Errorf("unknown tls mode: %s", s.cfg.TLS.Mode)
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.discovery.Stop()
	if s.reconciler != nil {
		s.reconciler.Stop()
	}
	s.store.Stop()
	if s.chalSrv != nil {
		s.chalSrv.Shutdown(ctx)
	}
	if s.httpSrv != nil {
		return s.httpSrv.Shutdown(ctx)
	}
	return nil
}
