package zdas

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ComposeClaims builds the full set of JWT claims for a ZDAS token from an
// upstream identity and device name, according to the ClaimsConfig.
func ComposeClaims(cfg ClaimsConfig, identity *UpstreamIdentity, deviceName string) map[string]interface{} {
	username := resolveUsername(cfg.UsernameClaim, identity)
	identityName := expandTemplate(cfg.NameTemplate, username, deviceName)
	externalID := computeExternalID(identity.Issuer, identity.Subject, deviceName)

	claims := map[string]interface{}{
		cfg.IdentityNameClaim: identityName,
		cfg.ExternalIDClaim:   externalID,
		"upstream_sub":        identity.Subject,
		"upstream_iss":        identity.Issuer,
		"preferred_username":  username,
		"device_name":         deviceName,
	}
	return claims
}

// MintToken signs a ZDAS JWT with the given claims, token config, and key set.
func MintToken(cfg TokenConfig, claims map[string]interface{}, ks *KeySet) (string, error) {
	now := time.Now()
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, cfg.Issuer)
	_ = tok.Set(jwt.AudienceKey, cfg.Audience)
	_ = tok.Set(jwt.IssuedAtKey, now)
	_ = tok.Set(jwt.ExpirationKey, now.Add(cfg.Expiry))

	for k, v := range claims {
		_ = tok.Set(k, v)
	}

	// Per spec: sub = device_external_id.
	if extID, ok := claims["device_external_id"].(string); ok {
		_ = tok.Set(jwt.SubjectKey, extID)
	}

	privJWK, err := jwk.FromRaw(ks.Private())
	if err != nil {
		return "", fmt.Errorf("wrap signing key: %w", err)
	}
	_ = privJWK.Set(jwk.KeyIDKey, ks.KID())
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privJWK))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return string(signed), nil
}

// resolveUsername picks the best username from the upstream identity. It checks
// the configured claim name first, then falls back through a chain.
func resolveUsername(claim string, identity *UpstreamIdentity) string {
	// Try the configured claim from the raw map.
	if claim != "" && identity.Raw != nil {
		if v, ok := identity.Raw[claim].(string); ok && v != "" {
			return v
		}
	}
	// Fallback chain: Username (already resolved by provider) -> Subject.
	if identity.Username != "" {
		return identity.Username
	}
	return identity.Subject
}

// expandTemplate replaces {username} and {device_name} in the template.
func expandTemplate(tmpl, username, deviceName string) string {
	s := strings.ReplaceAll(tmpl, "{username}", username)
	s = strings.ReplaceAll(s, "{device_name}", deviceName)
	return s
}

// computeExternalID returns the hex-encoded SHA-256 of issuer:subject:device,
// ensuring uniqueness across providers, users, and devices.
func computeExternalID(issuer, subject, deviceName string) string {
	raw := issuer + ":" + subject + ":" + deviceName
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}
