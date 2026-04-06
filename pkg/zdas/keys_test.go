package zdas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func TestGenerateKeySet(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}

	// Private key should be P-256.
	if ks.Private().Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
	if ks.KID() == "" {
		t.Error("kid is empty")
	}

	// Public JWK should carry the right metadata.
	k := ks.PublicJWK()
	if k.KeyType().String() != "EC" {
		t.Errorf("key type = %q, want EC", k.KeyType())
	}
	if k.Algorithm().String() != jwa.ES256.String() {
		t.Errorf("algorithm = %q, want ES256", k.Algorithm())
	}
	if k.KeyID() != ks.KID() {
		t.Errorf("kid on jwk = %q, want %q", k.KeyID(), ks.KID())
	}

	// Should not contain private material.
	var raw ecdsa.PublicKey
	if err := k.Raw(&raw); err != nil {
		t.Fatalf("extract raw public key: %v", err)
	}
}

func TestPublicJWKS(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	data, err := ks.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}

	// Must be valid JSON with a "keys" array containing one element.
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys count = %d, want 1", len(doc.Keys))
	}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	payload := []byte(`{"sub":"test"}`)

	// Sign with private key using ES256.
	privJWK, err := jwk.FromRaw(ks.Private())
	if err != nil {
		t.Fatalf("wrap private key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, ks.KID()); err != nil {
		t.Fatalf("set kid on private jwk: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		t.Fatalf("set alg on private jwk: %v", err)
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, privJWK))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify using just the public JWKS (what the controller would do).
	jwksBytes, err := ks.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	pubSet, err := jwk.Parse(jwksBytes)
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	verified, err := jws.Verify(signed, jws.WithKeySet(pubSet))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(verified) != string(payload) {
		t.Errorf("verified payload = %q, want %q", verified, payload)
	}
}

func TestTwoKeySetsProduceDifferentKeys(t *testing.T) {
	ks1, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet 1: %v", err)
	}
	ks2, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet 2: %v", err)
	}
	if ks1.KID() == ks2.KID() {
		t.Error("two independently generated key sets have the same kid")
	}
}
