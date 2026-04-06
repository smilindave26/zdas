package zdas

import (
	"crypto"
	"encoding/base64"
)

// jwkThumbprintHash is the hash algorithm used for RFC 7638 JWK thumbprints.
const jwkThumbprintHash = crypto.SHA256

// base64urlNoPad encodes raw bytes as base64url without padding,
// the encoding used for JWK thumbprints and PKCE values.
func base64urlNoPad(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
