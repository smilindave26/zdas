package zdas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// identityFile is the parsed content of a Ziti identity JSON file.
type identityFile struct {
	ZtAPI string `json:"ztAPI"`
	ID    struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
		CA   string `json:"ca"`
	} `json:"id"`
}

// parsedIdentity holds the decoded credentials from a Ziti identity file.
type parsedIdentity struct {
	APIURL  string
	TLSCert tls.Certificate
	CAPool  *x509.CertPool
}

// loadIdentityFile reads and parses a Ziti identity JSON file. The PEM fields
// may have an optional "pem:" prefix which is stripped.
func loadIdentityFile(path string) (*parsedIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	var idFile identityFile
	if err := json.Unmarshal(data, &idFile); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}

	certPEM := strings.TrimPrefix(idFile.ID.Cert, "pem:")
	keyPEM := strings.TrimPrefix(idFile.ID.Key, "pem:")
	caPEM := strings.TrimPrefix(idFile.ID.CA, "pem:")

	if certPEM == "" || keyPEM == "" {
		return nil, fmt.Errorf("identity file missing cert or key")
	}

	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse identity cert/key: %w", err)
	}

	var caPool *x509.CertPool
	if caPEM != "" {
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("no valid certificates in identity file CA")
		}
	}

	return &parsedIdentity{
		APIURL:  idFile.ZtAPI,
		TLSCert: tlsCert,
		CAPool:  caPool,
	}, nil
}

// discoveryClientFromIdentity builds an HTTP client that trusts the CA from
// the identity file but does not present a client certificate. This is used
// for unauthenticated calls to the public Edge Client API.
func discoveryClientFromIdentity(id *parsedIdentity) *http.Client {
	tlsCfg := &tls.Config{}
	if id.CAPool != nil {
		tlsCfg.RootCAs = id.CAPool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// managementClientFromIdentity builds an HTTP client with mTLS: the CA pool
// verifies the controller, and the client certificate authenticates ZDAS. This
// is used for the POST /authenticate call and subsequent management API calls.
func managementClientFromIdentity(id *parsedIdentity) *http.Client {
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{id.TLSCert},
	}
	if id.CAPool != nil {
		tlsCfg.RootCAs = id.CAPool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// bootstrapCAPool fetches the controller's CA certificates from
// /.well-known/est/cacerts using an insecure TLS client, then returns a cert
// pool built from the response. This allows ZDAS to trust the controller's
// TLS certificate without a pre-configured CA file or identity file. Falls
// back to the system cert pool if the fetch fails.
func bootstrapCAPool(controllerURL string) (*x509.CertPool, error) {
	insecureClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	reqURL := strings.TrimSuffix(controllerURL, "/") + "/.well-known/est/cacerts"
	resp, err := insecureClient.Get(reqURL)
	if err != nil {
		return systemOrEmptyPool(), nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		return systemOrEmptyPool(), nil
	}

	// The response is base64-encoded DER (PKCS#7) per RFC 7030. Decode the
	// base64 layer, then parse the DER certificates.
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	n, err := base64.StdEncoding.Decode(decoded, body)
	if err != nil {
		// Maybe it's PEM instead of base64 DER. Try PEM parsing.
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(body) {
			return pool, nil
		}
		return systemOrEmptyPool(), nil
	}
	decoded = decoded[:n]

	certs, err := x509.ParseCertificates(decoded)
	if err != nil {
		return systemOrEmptyPool(), nil
	}

	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}

func systemOrEmptyPool() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	return pool
}

// apiSession holds the result of a POST /authenticate call.
type apiSession struct {
	Token     string
	ExpiresAt time.Time
}

// authenticateSession performs a certificate-based authentication against the
// Ziti controller management API. It returns a session token that must be
// passed as the zt-session header on subsequent management API calls.
func authenticateSession(client *http.Client, apiURL string) (*apiSession, error) {
	authURL := strings.TrimSuffix(apiURL, "/") + "/authenticate?method=cert"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, authURL, strings.NewReader("{}"))
	if err != nil {
		return nil, fmt.Errorf("build authenticate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authenticate request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authenticate returned %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Token             *string `json:"token"`
			ExpiresAt         string  `json:"expiresAt"`
			ExpirationSeconds *int    `json:"expirationSeconds"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse authenticate response: %w", err)
	}
	if result.Data.Token == nil || *result.Data.Token == "" {
		return nil, fmt.Errorf("api session token was empty")
	}

	expiresAt := time.Now().Add(25 * time.Minute) // default
	if result.Data.ExpirationSeconds != nil && *result.Data.ExpirationSeconds > 0 {
		expiresAt = time.Now().Add(time.Duration(*result.Data.ExpirationSeconds) * time.Second)
	} else if result.Data.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, result.Data.ExpiresAt); err == nil {
			expiresAt = t
		}
	}

	return &apiSession{Token: *result.Data.Token, ExpiresAt: expiresAt}, nil
}
