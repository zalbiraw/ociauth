// Package ociauth is a Traefik plugin that adds Oracle Cloud Infrastructure (OCI)
// Instance Principal authentication to HTTP requests.
//
// The plugin adds OCI signature authentication headers to requests, allowing them to authenticate
// with OCI services using Instance Principal authentication. This is particularly useful for
// applications running on OCI compute instances that need to access OCI services.
//
// Key features:
// - Instance Principal authentication with certificate caching
// - Automatic signature generation for OCI API requests
// - Thread-safe credential management
// - Comprehensive error handling and logging
// - Configurable authentication type
package ociauth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/zalbiraw/ociauth/internal"
)

// Config represents the configuration for the OCI Instance Principal Auth plugin.
type Config struct {
	// AuthType specifies the OCI authentication method to use.
	// Currently only "instance_principal" is supported.
	AuthType string `json:"authType,omitempty" yaml:"authType,omitempty"`

	// ServiceName specifies the OCI service to authenticate against.
	// Currently only "generativeai" is supported.
	ServiceName string `json:"serviceName,omitempty" yaml:"serviceName,omitempty"`

	// Region specifies the OCI region for the service endpoint.
	// Example: "us-chicago-1", "us-ashburn-1", "eu-frankfurt-1"
	Region string `json:"region,omitempty" yaml:"region,omitempty"`
}

// AuthPlugin represents the main plugin instance that handles OCI authentication.
type AuthPlugin struct {
	next        http.Handler // Next handler in the middleware chain
	name        string       // Plugin instance name
	client      *http.Client // HTTP client for OCI metadata service
	serviceName string       // OCI service name
	region      string       // OCI region
}

// New creates a new OCI Instance Principal Auth plugin instance.
// Validates the auth type configuration and sets defaults if needed.
//
// Parameters:
//   - ctx: Context for the plugin initialization
//   - next: Next HTTP handler in the middleware chain
//   - cfg: Plugin configuration
//   - name: Name of the plugin instance
//
// Returns the configured plugin handler.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	// Set default auth type if not specified
	if cfg.AuthType == "" {
		cfg.AuthType = "instance_principal"
	}

	// Validate auth type
	if cfg.AuthType != "instance_principal" {
		return nil, fmt.Errorf("unsupported auth type '%s', only 'instance_principal' is supported", cfg.AuthType)
	}

	// Set default service name if not specified
	if cfg.ServiceName == "" {
		cfg.ServiceName = "generativeai"
	}

	// Validate service name
	if cfg.ServiceName != "generativeai" {
		return nil, fmt.Errorf("unsupported service name '%s', only 'generativeai' is supported", cfg.ServiceName)
	}

	// Validate region is required
	if cfg.Region == "" {
		return nil, fmt.Errorf("region is required")
	}

	log.Printf("Initializing OCI Instance Principal Auth plugin %s with auth type: %s, service: %s, region: %s",
		name, cfg.AuthType, cfg.ServiceName, cfg.Region)

	return &AuthPlugin{
		next:        next,
		name:        name,
		serviceName: cfg.ServiceName,
		region:      cfg.Region,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// generateOCIHost generates the OCI service endpoint host based on service name and region.
func (a *AuthPlugin) generateOCIHost() string {
	return fmt.Sprintf("%s.%s.oci.oraclecloud.com", a.serviceName, a.region)
}

// ServeHTTP implements the http.Handler interface and adds OCI authentication to requests.
//
// The plugin processes all incoming requests and adds the necessary OCI signature authentication
// headers. The authentication headers include:
// - Date header (required for OCI signature)
// - Content-Type header (for POST/PUT requests)
// - Content-Length header (for requests with body)
// - X-Content-SHA256 header (SHA256 hash of request body)
// - Authorization header (OCI signature)
//
// For requests without authentication requirements, they are passed through unchanged.
func (a *AuthPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log.Printf("[%s] Processing request: %s %s", a.name, req.Method, req.URL.String())

	// Set OCI service host and HTTPS scheme for consistent signature calculation
	ociHost := a.generateOCIHost()
	req.URL.Scheme = "https"
	req.URL.Host = ociHost
	req.Host = ociHost
	log.Printf("[%s] Set OCI URL to: %s", a.name, req.URL.String())

	// Set required headers for OCI signature if not already present
	if req.Header.Get("Date") == "" {
		req.Header.Set("Date", time.Now().Format(time.RFC1123))
	}

	if req.Header.Get("Content-Type") == "" && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		req.Header.Set("Content-Type", "application/json")
	}

	// This is essential because the OCI signature includes the content-length header
	if req.ContentLength >= 0 {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", req.ContentLength))
	}

	// Add OCI authentication headers
	if err := a.signRequest(req); err != nil {
		log.Printf("[%s] OCI auth failed: %v", err)
		http.Error(rw, fmt.Sprintf("OCI authentication failed: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[%s] OCI authentication successful", a.name)

	// Forward the authenticated request
	a.next.ServeHTTP(rw, req)
}

// signRequest adds OCI authentication headers to the given HTTP request.
// It uses cached credentials when available or fetches fresh ones if needed.
func (a *AuthPlugin) signRequest(req *http.Request) (err error) {
	// Add panic recovery to prevent yaegi interpreter crashes
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("authentication panic recovered: %v", r)
			log.Printf("[%s] Panic during authentication: %v", a.name, r)
		}
	}()

	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	keyProvider, err := internal.NewInstancePrincipalKeyProvider(nil)
	if err != nil {
		log.Printf("[%s] Failed to create key provider: %v", a.name, err)
		return fmt.Errorf("failed to create key provider: %w", err)
	}

	if keyProvider == nil {
		log.Printf("[%s] Key provider is nil", a.name)
		return fmt.Errorf("key provider is nil")
	}

	signer := internal.DefaultRequestSigner(keyProvider)
	if signer == nil {
		log.Printf("[%s] Signer is nil", a.name)
		return fmt.Errorf("signer is nil")
	}

	if err := signer.Sign(req); err != nil {
		log.Printf("[%s] Failed to sign request: %v", a.name, err)
		return fmt.Errorf("failed to sign request: %w", err)
	}

	return nil
}

// CreateConfig creates the default plugin configuration.
// This function is required by Traefik's plugin system.
func CreateConfig() *Config {
	return &Config{
		AuthType:    "instance_principal",
		ServiceName: "generativeai",
		Region:      "", // Must be provided by user
	}
}
