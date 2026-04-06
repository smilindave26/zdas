package zdas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// KeySet is an EC P-256 signing key pair plus its public JWK representation.
// It is generated once at startup; on restart a new key is produced and the
// JWKS endpoint immediately reflects it. Old tokens signed with previous keys
// become unverifiable, which is acceptable because enrollment tokens are
// short-lived and single-use.
type KeySet struct {
	private *ecdsa.PrivateKey
	publicJWK jwk.Key
	kid       string
}

// GenerateKeySet creates a fresh EC P-256 key pair and wraps it in a KeySet.
// The key ID is the RFC 7638 JWK thumbprint of the public key, so it is
// deterministic and cryptographically bound to the key material.
func GenerateKeySet() (*KeySet, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ec key: %w", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("wrap public key as jwk: %w", err)
	}
	thumb, err := pub.Thumbprint(jwkThumbprintHash)
	if err != nil {
		return nil, fmt.Errorf("compute jwk thumbprint: %w", err)
	}
	kid := base64urlNoPad(thumb)
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, fmt.Errorf("set alg: %w", err)
	}
	if err := pub.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("set use: %w", err)
	}
	return &KeySet{private: priv, publicJWK: pub, kid: kid}, nil
}

// KID returns the key ID (JWK thumbprint) used to identify this key in JWS
// headers and in the JWKS document.
func (ks *KeySet) KID() string { return ks.kid }

// Private returns the raw ECDSA private key for signing operations.
func (ks *KeySet) Private() *ecdsa.PrivateKey { return ks.private }

// PublicJWK returns the public key as a jwk.Key with kid/alg/use set.
func (ks *KeySet) PublicJWK() jwk.Key { return ks.publicJWK }

// PublicJWKS returns the marshaled JWKS JSON containing the single public key,
// suitable for serving from GET /.well-known/jwks.json.
func (ks *KeySet) PublicJWKS() ([]byte, error) {
	set := jwk.NewSet()
	if err := set.AddKey(ks.publicJWK); err != nil {
		return nil, fmt.Errorf("add key to set: %w", err)
	}
	return json.Marshal(set)
}
