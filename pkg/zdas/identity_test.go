package zdas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fullsailor/pkcs7"
)

// generateTestIdentityFile creates a temporary Ziti identity JSON file with a
// self-signed cert, key, and CA for testing. Returns the file path.
func generateTestIdentityFile(t *testing.T, apiURL string) string {
	t.Helper()

	// Generate CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Generate client cert signed by CA.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "zdas-admin"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})

	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	idFile := map[string]interface{}{
		"ztAPI": apiURL,
		"id": map[string]string{
			"cert": string(clientCertPEM),
			"key":  string(clientKeyPEM),
			"ca":   string(caPEM),
		},
	}
	data, _ := json.Marshal(idFile)

	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	return path
}

func TestLoadIdentityFile(t *testing.T) {
	path := generateTestIdentityFile(t, "https://ctrl.example.com:1280")
	id, err := loadIdentityFile(path)
	if err != nil {
		t.Fatalf("loadIdentityFile: %v", err)
	}
	if id.APIURL != "https://ctrl.example.com:1280" {
		t.Errorf("APIURL = %q", id.APIURL)
	}
	if id.CAPool == nil {
		t.Error("CAPool is nil")
	}
	if len(id.TLSCert.Certificate) == 0 {
		t.Error("TLSCert has no certificates")
	}
}

func TestLoadIdentityFileWithPEMPrefix(t *testing.T) {
	// Generate raw PEM strings, then prefix with "pem:".
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	keyDER, _ := x509.MarshalECPrivateKey(clientKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	idFile := map[string]interface{}{
		"ztAPI": "https://ctrl:1280",
		"id": map[string]string{
			"cert": "pem:" + certPEM,
			"key":  "pem:" + keyPEM,
			"ca":   "pem:" + caPEM,
		},
	}
	data, _ := json.Marshal(idFile)
	path := filepath.Join(t.TempDir(), "id.json")
	os.WriteFile(path, data, 0o600)

	id, err := loadIdentityFile(path)
	if err != nil {
		t.Fatalf("loadIdentityFile with pem: prefix: %v", err)
	}
	if id.CAPool == nil {
		t.Error("CAPool is nil")
	}
}

func TestLoadIdentityFileMissing(t *testing.T) {
	_, err := loadIdentityFile("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadIdentityFileMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("not json"), 0o600)

	_, err := loadIdentityFile(path)
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestLoadIdentityFileMissingCert(t *testing.T) {
	idFile := map[string]interface{}{
		"ztAPI": "https://ctrl:1280",
		"id": map[string]string{
			"key": "some-key",
			"ca":  "some-ca",
		},
	}
	data, _ := json.Marshal(idFile)
	path := filepath.Join(t.TempDir(), "nocert.json")
	os.WriteFile(path, data, 0o600)

	_, err := loadIdentityFile(path)
	if err == nil || !strings.Contains(err.Error(), "missing cert") {
		t.Errorf("expected missing cert error, got %v", err)
	}
}

func TestDiscoveryClientFromIdentity(t *testing.T) {
	path := generateTestIdentityFile(t, "https://ctrl:1280")
	id, _ := loadIdentityFile(path)
	client := discoveryClientFromIdentity(id)
	if client == nil {
		t.Fatal("client is nil")
	}
	if client.Timeout != 15*time.Second {
		t.Errorf("timeout = %v", client.Timeout)
	}
}

func TestBootstrapCAPoolFromEST(t *testing.T) {
	// Generate a self-signed CA cert to serve from the mock EST endpoint.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	// Wrap the cert in PKCS#7 and serve as base64 (EST format, matching what
	// the Ziti controller returns).
	caCert, _ := x509.ParseCertificate(caDER)
	p7Data, err := pkcs7.DegenerateCertificate(caCert.Raw)
	if err != nil {
		t.Fatalf("create pkcs7: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/est/cacerts" {
			w.Header().Set("Content-Type", "application/pkcs7-mime")
			encoded := base64.StdEncoding.EncodeToString(p7Data)
			w.Write([]byte(encoded))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	pool, err := bootstrapCAPool(server.URL)
	if err != nil {
		t.Fatalf("bootstrapCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}
	// Verify the pool contains the CA.
	_, err = caCert.Verify(x509.VerifyOptions{Roots: pool})
	if err != nil {
		t.Errorf("pool should contain the bootstrapped CA: %v", err)
	}
}

func TestBootstrapCAPoolFallsBackOnFailure(t *testing.T) {
	// Unreachable controller - should fall back to system pool, not error.
	pool, err := bootstrapCAPool("https://127.0.0.1:1")
	if err != nil {
		t.Fatalf("expected fallback, got error: %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}
}

func TestManagementClientFromIdentity(t *testing.T) {
	path := generateTestIdentityFile(t, "https://ctrl:1280")
	id, _ := loadIdentityFile(path)
	client := managementClientFromIdentity(id)
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestAuthenticateSession(t *testing.T) {
	token := "test-zt-session-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authenticate" || r.URL.Query().Get("method") != "cert" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.Error(w, "bad", 400)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"token":"%s","expirationSeconds":1800}}`, token)
	}))
	t.Cleanup(server.Close)

	session, err := authenticateSession(server.Client(), server.URL)
	if err != nil {
		t.Fatalf("authenticateSession: %v", err)
	}
	if session.Token != token {
		t.Errorf("Token = %q", session.Token)
	}
	if session.ExpiresAt.Before(time.Now().Add(29 * time.Minute)) {
		t.Errorf("ExpiresAt too early: %v", session.ExpiresAt)
	}
}

func TestAuthenticateSessionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	_, err := authenticateSession(server.Client(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected auth error, got %v", err)
	}
}
