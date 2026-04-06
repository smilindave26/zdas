# ZDAS - Ziti Device Authentication Service

ZDAS is a lightweight Go service that solves a specific problem with [OpenZiti](https://openziti.io) device enrollment: standard OIDC providers issue tokens about *users*, not *devices*. If the same user enrolls from three devices, the tokens are identical and the second and third enrollments fail because the external ID collides.

ZDAS sits between the tunneler and your upstream identity provider, delegates user authentication to the IdP, collects device info from the tunneler, and mints its own JWT that combines both. Each device gets a unique Ziti identity via `enroll-to-cert`.

## How it works

```
Tunneler          ZDAS              Upstream IdP       Ziti Controller
   |                |                    |                   |
   |-- /authorize ->|                    |                   |
   |   (device info)|                    |                   |
   |                |-- /authorize ----->|                   |
   |                |   (PKCE, user auth)|                   |
   |                |<-- callback -------|                   |
   |                |                    |                   |
   |                | compose claims:    |                   |
   |                |   username + device |                   |
   |                | sign with own key  |                   |
   |                |                    |                   |
   |<-- ZDAS JWT ---|                    |                   |
   |                                                         |
   |-- enroll-to-cert (Bearer ZDAS JWT) -------------------->|
   |                                     validates via JWKS ->|
   |                                     creates identity     |
```

ZDAS discovers upstream IdPs automatically by polling the controller's public `external-jwt-signers` endpoint - no parallel IdP configuration needed. Non-OIDC providers like GitHub (which issues opaque tokens, not JWTs) can be configured directly.

When multiple identity providers are available, ZDAS presents a selection page in the browser so the user can choose where to authenticate.

## Features

- **Single binary, no database.** Ephemeral EC P-256 keys generated at startup, served via JWKS. In-memory session store with automatic cleanup.
- **Controller-driven IdP discovery.** ZDAS polls the Ziti controller for ext-jwt-signers with `enrollToCertEnabled`, so adding a new IdP to the controller automatically makes it available through ZDAS.
- **Non-OIDC provider support.** GitHub (and other OAuth-only providers) can be configured directly. Both discovered and configured providers are unified behind a common `UpstreamProvider` interface.
- **Fallback for unmodified tunnelers.** Deploy ZDAS before updating any tunnelers. Unmodified tunnelers enroll with a temporary name, and ZDAS renames the identity via the management API after the tunneler connects and reports `envInfo`. Set `fallback.enabled: false` once all tunnelers are updated.
- **Three TLS modes.** `acme` (automatic Let's Encrypt), `static` (bring your own cert), or `none` (behind a reverse proxy).
- **Embeddable.** `pkg/zdas` is an importable Go package. Mount the handler on your own mux or run it standalone.

## Quick start

```bash
# Build
go build -o zdas ./cmd/zdas/

# Configure (see config.example.yaml for all options)
cp config.example.yaml config.yaml
# Edit config.yaml: set external_url, controller.api_url

# Register ZDAS as an ext-jwt-signer on the controller
ziti edge create ext-jwt-signer zdas-signer \
  "https://das.example.com" \
  --jwks-endpoint "https://das.example.com/.well-known/jwks.json" \
  --external-auth-url "https://das.example.com/authorize" \
  --audience "ziti-enrolltocert" \
  --client-id "ziti-enrolltocert" \
  --enroll-to-cert \
  --enroll-name-claims-selector "device_identity_name" \
  --claims-property "device_external_id" \
  --use-external-id

# Run
./zdas -config config.yaml
```

## Configuration

ZDAS is configured via YAML, environment variables, or both (env vars override YAML). See [`config.example.yaml`](config.example.yaml) for the full reference.

Key settings:

| Setting | Description | Default |
|---------|-------------|---------|
| `external_url` | Public URL where tunnelers and the controller reach ZDAS | (required) |
| `controller.api_url` | Ziti controller Edge Client API URL | (required) |
| `controller.identity_file` | Ziti admin identity JSON (cert, key, CA) for management API | (optional, required for fallback) |
| `fallback.enabled` | Allow enrollment without device info from unmodified tunnelers | `false` |
| `claims.name_template` | Template for identity names. Placeholders: `{username}`, `{device_name}`, `{hostname}`, `{os}`, `{arch}` | `{username}-{device_name}` |
| `token.expiry` | How long enrollment tokens are valid | `5m` |
| `tls.mode` | `none`, `static`, or `acme` | `none` |

Environment variable overrides follow the pattern `ZDAS_SECTION_FIELD`, e.g. `ZDAS_CONTROLLER_API_URL`, `ZDAS_FALLBACK_ENABLED`, `ZDAS_PROVIDER_GITHUB_CLIENT_SECRET`.

## Tunneler integration

Updated tunnelers send device info as query parameters on the authorize URL:

- `device_name` - primary device identifier (hostname, machine-id, or user-chosen name)
- `hostname`, `os`, `arch`, `os_release`, `os_version` - optional, for richer identity names

Unmodified tunnelers work without changes when `fallback.enabled` is true. They enroll with a temporary name (e.g., `jsmith-pending-a3f9b2`) that ZDAS reconciles to the real hostname after the tunneler connects.

## Embedding

```go
import "github.com/smilindave26/zdas/pkg/zdas"

handler, err := zdas.NewHandler(cfg, logger)
mux.Handle("/device-auth/", http.StripPrefix("/device-auth", handler))
// ... on shutdown:
handler.Stop()
```

## Project layout

```
cmd/zdas/          standalone binary
pkg/zdas/
  config.go        configuration and validation
  keys.go          EC P-256 key generation and JWKS
  provider.go      UpstreamProvider interface and registry
  oidc.go          OIDC provider (from discovered signers)
  github.go        GitHub OAuth provider
  discovery.go     controller-driven IdP discovery
  claims.go        claim composition and JWT minting
  handlers.go      HTTP endpoints (/authorize, /callback, /token, OIDC discovery, JWKS)
  session.go       in-memory session and auth code store
  identity.go      Ziti identity file parsing and management API auth
  reconciler.go    fallback identity reconciliation
  server.go        server assembly and TLS modes
  acme.go          Let's Encrypt autocert
```

## License

Apache 2.0. See [LICENSE](LICENSE).
