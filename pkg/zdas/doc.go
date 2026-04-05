// Package zdas implements the Ziti Device Authentication Service: an
// OIDC-compliant authorization server that sits between OpenZiti tunnelers
// and an upstream IdP, injecting device-specific claims into JWTs so that
// each device a user enrolls from gets a unique Ziti identity.
package zdas
