package zdas

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func defaultClaimsConfig() ClaimsConfig {
	return ClaimsConfig{
		UsernameClaim:     "preferred_username",
		NameTemplate:      "{username}-{device_name}",
		IdentityNameClaim: "device_identity_name",
		ExternalIDClaim:   "device_external_id",
	}
}

func TestComposeClaimsBasic(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "u42",
		Username: "jsmith",
		Issuer:   "https://keycloak.example.com",
		Raw:      map[string]interface{}{"preferred_username": "jsmith", "sub": "u42"},
	}
	info := &DeviceInfo{DeviceName: "macbook-pro", Hostname: "macbook-pro", OS: "darwin", Arch: "arm64"}
	claims := ComposeClaims(defaultClaimsConfig(), FallbackConfig{}, identity, info, "")

	if got := claims["device_identity_name"]; got != "jsmith-macbook-pro" {
		t.Errorf("device_identity_name = %q", got)
	}
	if got, ok := claims["device_external_id"].(string); !ok || len(got) != 64 {
		t.Errorf("device_external_id = %q (expected 64-char hex)", got)
	}
	if got := claims["upstream_sub"]; got != "u42" {
		t.Errorf("upstream_sub = %v", got)
	}
	if got := claims["upstream_iss"]; got != "https://keycloak.example.com" {
		t.Errorf("upstream_iss = %v", got)
	}
	if got := claims["device_name"]; got != "macbook-pro" {
		t.Errorf("device_name = %v", got)
	}
}

func TestComposeClaimsUsernameFallback(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "sub1",
		Username: "fallback-user",
		Issuer:   "https://idp",
		Raw:      map[string]interface{}{},
	}
	claims := ComposeClaims(defaultClaimsConfig(), FallbackConfig{}, identity, &DeviceInfo{DeviceName: "laptop"}, "")
	if got := claims["device_identity_name"]; got != "fallback-user-laptop" {
		t.Errorf("identity name with fallback = %q", got)
	}
}

func TestComposeClaimsSubjectFallback(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject: "anon-sub",
		Issuer:  "https://idp",
		Raw:     map[string]interface{}{},
	}
	claims := ComposeClaims(defaultClaimsConfig(), FallbackConfig{}, identity, &DeviceInfo{DeviceName: "phone"}, "")
	if got := claims["device_identity_name"]; got != "anon-sub-phone" {
		t.Errorf("identity name with subject fallback = %q", got)
	}
}

func TestComposeClaimsFallback(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "u42",
		Username: "jsmith",
		Issuer:   "https://keycloak",
		Raw:      map[string]interface{}{"preferred_username": "jsmith"},
	}
	fbCfg := FallbackConfig{
		Enabled:          true,
		TempNameTemplate: "{username}-pending-{nonce_short}",
	}
	claims := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, nil, "a3f9b2")

	if got := claims["device_identity_name"]; got != "jsmith-pending-a3f9b2" {
		t.Errorf("fallback identity name = %q", got)
	}
	if got, ok := claims["device_external_id"].(string); !ok || len(got) != 64 {
		t.Errorf("fallback external_id = %q", got)
	}
	if got := claims["device_name"]; got != "" {
		t.Errorf("fallback device_name should be empty, got %q", got)
	}
}

func TestComposeClaimsFallbackWithPartialDeviceInfo(t *testing.T) {
	identity := &UpstreamIdentity{
		Subject:  "u42",
		Username: "jsmith",
		Issuer:   "https://keycloak",
		Raw:      map[string]interface{}{"preferred_username": "jsmith"},
	}
	fbCfg := FallbackConfig{
		Enabled:          true,
		TempNameTemplate: "{username}-pending-{nonce_short}",
	}
	// Partial DeviceInfo: no device_name, but OS is known (e.g. iOS tunneler).
	info := &DeviceInfo{OS: "iOS", Arch: "arm64"}
	claims := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, info, "a3f9b2")

	// Nonce triggers fallback path even when DeviceInfo is non-nil.
	if got := claims["device_identity_name"]; got != "jsmith-pending-a3f9b2" {
		t.Errorf("fallback identity name = %q, want jsmith-pending-a3f9b2", got)
	}
	if got := claims["device_name"]; got != "" {
		t.Errorf("fallback device_name should be empty, got %q", got)
	}
}

func TestComposeClaimsFallbackUniqueExternalIDs(t *testing.T) {
	identity := &UpstreamIdentity{Subject: "u1", Issuer: "https://idp"}
	fbCfg := FallbackConfig{TempNameTemplate: "{username}-pending-{nonce_short}"}

	c1 := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, nil, "aaaaaa")
	c2 := ComposeClaims(defaultClaimsConfig(), fbCfg, identity, nil, "bbbbbb")

	if c1["device_external_id"] == c2["device_external_id"] {
		t.Error("different nonces should produce different external IDs")
	}
}

func TestExpandFallbackTemplate(t *testing.T) {
	got := expandFallbackTemplate("{username}-pending-{nonce_short}", "alice", "abc123")
	if got != "alice-pending-abc123" {
		t.Errorf("expandFallbackTemplate = %q", got)
	}
}

func TestExternalIDDiffersByDevice(t *testing.T) {
	id1 := computeExternalID("iss", "sub", "device-a")
	id2 := computeExternalID("iss", "sub", "device-b")
	if id1 == id2 {
		t.Error("same user on different devices should produce different external IDs")
	}
}

func TestExternalIDDiffersByIssuer(t *testing.T) {
	id1 := computeExternalID("https://keycloak", "12345", "laptop")
	id2 := computeExternalID("https://github.com", "12345", "laptop")
	if id1 == id2 {
		t.Error("same sub from different issuers should produce different external IDs")
	}
}

func TestExpandTemplate(t *testing.T) {
	cases := []struct {
		tmpl, user string
		info       *DeviceInfo
		want       string
	}{
		{"{username}-{device_name}", "alice", &DeviceInfo{DeviceName: "macbook"}, "alice-macbook"},
		{"{device_name}@{username}", "bob", &DeviceInfo{DeviceName: "phone"}, "phone@bob"},
		{"prefix-{username}-{device_name}-suffix", "u", &DeviceInfo{DeviceName: "d"}, "prefix-u-d-suffix"},
		{"{username}-{hostname}", "alice", &DeviceInfo{Hostname: "macbook-pro.local"}, "alice-macbook-pro.local"},
		{"{username}-{device_name}-{os}-{arch}", "bob", &DeviceInfo{DeviceName: "laptop", OS: "darwin", Arch: "arm64"}, "bob-laptop-darwin-arm64"},
	}
	for _, tc := range cases {
		got := expandTemplate(tc.tmpl, tc.user, tc.info)
		if got != tc.want {
			t.Errorf("expandTemplate(%q, %q, %+v) = %q, want %q", tc.tmpl, tc.user, tc.info, got, tc.want)
		}
	}
}

func TestMintTokenRoundtrip(t *testing.T) {
	ks, err := GenerateKeySet()
	if err != nil {
		t.Fatalf("GenerateKeySet: %v", err)
	}
	identity := &UpstreamIdentity{
		Subject:  "u1",
		Username: "alice",
		Issuer:   "https://idp",
		Raw:      map[string]interface{}{"preferred_username": "alice"},
	}
	cfg := defaultClaimsConfig()
	claims := ComposeClaims(cfg, FallbackConfig{}, identity, &DeviceInfo{DeviceName: "laptop"}, "")

	tokenCfg := TokenConfig{
		Issuer:   "https://zdas.example.com",
		Audience: "ziti-enrolltocert",
		Expiry:   300_000_000_000, // 5 min in nanoseconds
	}
	signed, err := MintToken(tokenCfg, claims, ks)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	jwksBytes, _ := ks.PublicJWKS()
	pubSet, _ := jwk.Parse(jwksBytes)
	tok, err := jwt.Parse([]byte(signed), jwt.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("parse+verify: %v", err)
	}

	if tok.Issuer() != "https://zdas.example.com" {
		t.Errorf("issuer = %q", tok.Issuer())
	}
	idName, _ := tok.Get("device_identity_name")
	if idName != "alice-laptop" {
		t.Errorf("device_identity_name = %v", idName)
	}
	extID, _ := tok.Get("device_external_id")
	if extID == nil || extID == "" {
		t.Error("device_external_id missing from token")
	}
	if tok.Subject() != extID {
		t.Errorf("sub = %q, device_external_id = %q, want equal", tok.Subject(), extID)
	}
}
