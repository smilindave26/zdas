package zdas

import (
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// listenACME starts the HTTPS server with automatic Let's Encrypt certificates.
// If the main listen address is not :443, it starts a secondary listener on :443
// for the TLS-ALPN-01 challenge.
func (s *Server) listenACME() error {
	m := &autocert.Manager{
		Cache:      autocert.DirCache(s.cfg.TLS.ACME.CacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.cfg.TLS.ACME.Domains...),
	}

	s.httpSrv.TLSConfig = m.TLSConfig()

	if s.cfg.Listen != ":443" {
		go func() {
			chalSrv := &http.Server{
				Addr:    ":443",
				Handler: m.HTTPHandler(nil),
			}
			if err := chalSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				s.logger.Error("acme challenge listener failed", "error", err)
			}
		}()
	}

	return s.httpSrv.ListenAndServeTLS("", "")
}
