package zdas

import "context"

// EnrollmentProvisioner is an optional hook for embedding applications. When
// set, ZDAS calls Provision after upstream authentication succeeds instead of
// using its built-in claim composition. The provisioner handles user lookup,
// network assignment, and device creation in the embedding application's data
// model.
type EnrollmentProvisioner interface {
	// Provision is called after upstream auth succeeds. Return
	// ProvisionResult with Claims set to proceed immediately (mint the JWT).
	// Return ProvisionResult with RedirectURL set to redirect the browser
	// to an application-hosted page (e.g., network picker) for interactive
	// selection before completing the flow.
	Provision(ctx context.Context, req ProvisionRequest) (*ProvisionResult, error)
}

// ProvisionRequest contains everything the provisioner needs to make decisions
// about user and device provisioning.
type ProvisionRequest struct {
	// From upstream IdP (after successful authentication).
	Email    string // user's email address
	Name     string // display name
	Subject  string // stable user ID (OIDC sub, GitHub numeric ID)
	Provider string // provider name ("google", "github", etc.)

	// From tunneler query params on /authorize. DeviceName and other fields
	// will be empty for unmodified tunnelers (fallback path).
	DeviceName string
	Hostname   string
	OS         string
	Arch       string
	OSRelease  string
	OSVersion  string

	// True when the tunneler didn't send device info (fallback path).
	IsFallback    bool
	FallbackNonce string
}

// ProvisionResult tells ZDAS how to proceed after provisioning.
type ProvisionResult struct {
	// Claims to include in the ZDAS JWT. When non-nil, ZDAS mints the token
	// immediately. The map should include at minimum the identity name claim
	// and external ID claim from ClaimsConfig.
	Claims map[string]interface{}

	// RedirectURL, when non-empty and Claims is nil, redirects the browser
	// to an application-hosted page for interactive selection. The page must
	// call POST /provision/complete to finish the flow.
	RedirectURL string
}

// Option configures optional behavior on NewServer / NewHandler.
type Option func(*serverOptions)

type serverOptions struct {
	provisioner EnrollmentProvisioner
}

// WithProvisioner sets an EnrollmentProvisioner hook. When set, ZDAS calls
// it after upstream authentication instead of using built-in claim composition.
func WithProvisioner(p EnrollmentProvisioner) Option {
	return func(o *serverOptions) { o.provisioner = p }
}
