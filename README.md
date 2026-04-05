# ZDAS - Ziti Device Authentication Service

A lightweight Go service that acts as an OIDC-compliant authorization server
for OpenZiti device enrollment. ZDAS sits between a tunneler and an upstream
IdP, collects device info from the tunneler, delegates user authentication to
the IdP, and mints its own JWT combining both - so each device a user enrolls
from gets a unique Ziti identity via `enroll-to-cert`.

## Status

Early bootstrap. Not yet functional.

## Layout

- `cmd/zdas/` - standalone binary entry point
- `pkg/zdas/` - importable package containing all server logic

## Build

```
go build ./...
```
