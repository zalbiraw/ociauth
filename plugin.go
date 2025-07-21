// Package ociinstanceprincipalauth is a Traefik plugin that adds Oracle Cloud Infrastructure (OCI)
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
// - No configuration required - works automatically on OCI compute instances
package ociinstanceprincipalauth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/zalbiraw/ociinstanceprincipalauth/internal"
)

// Config represents the configuration for the OCI Instance Principal Auth plugin.
// This plugin requires no configuration as it automatically detects OCI compute instances
// and uses Instance Principal authentication.
type Config struct {
	// No configuration fields needed - Instance Principal authentication works automatically
}

// AuthPlugin represents the main plugin instance that handles OCI authentication.
type AuthPlugin struct {
	next   http.Handler   // Next handler in the middleware chain
	name   string         // Plugin instance name
	client *http.Client   // HTTP client for OCI metadata service
}

// New creates a new OCI Instance Principal Auth plugin instance.
// No configuration validation is needed as the plugin works automatically.
//
// Parameters:
//   - ctx: Context for the plugin initialization
//   - next: Next HTTP handler in the middleware chain
//   - cfg: Plugin configuration (not used)
//   - name: Name of the plugin instance
//
// Returns the configured plugin handler.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	log.Printf("Initializing OCI Instance Principal Auth plugin %s", name)

	return &AuthPlugin{
		next: next,
		name: name,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
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
	log.Printf("[%s] === OCI AUTH REQUEST START ===", a.name)
	log.Printf("[%s] Processing request: %s %s", a.name, req.Method, req.URL.Path)
	log.Printf("[%s] Request Host: %s", a.name, req.Host)

	// Check if this is an OCI API request (requests to *.oci.oraclecloud.com)
	if !a.isOCIRequest(req) {
		log.Printf("[%s] Not an OCI request, passing through without authentication", a.name)
		a.next.ServeHTTP(rw, req)
		log.Printf("[%s] === OCI AUTH REQUEST END (passthrough) ===", a.name)
		return
	}

	log.Printf("[%s] OCI request detected, adding authentication", a.name)

	// Set required headers for OCI signature if not already present
	if req.Header.Get("Date") == "" {
		req.Header.Set("Date", time.Now().Format(time.RFC1123))
		log.Printf("[%s] Added Date header", a.name)
	}

	if req.Header.Get("Content-Type") == "" && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		req.Header.Set("Content-Type", "application/json")
		log.Printf("[%s] Added Content-Type header", a.name)
	}

	// Add OCI authentication headers
	log.Printf("[%s] Signing request with OCI Instance Principal authentication", a.name)
	if err := a.signRequest(req); err != nil {
		log.Printf("[%s] Authentication error: %v", a.name, err)
		http.Error(rw, fmt.Sprintf("OCI authentication failed: %v", err), http.StatusInternalServerError)
		log.Printf("[%s] === OCI AUTH REQUEST END (error) ===", a.name)
		return
	}
	log.Printf("[%s] Request signed successfully", a.name)

	// Log the authentication headers that were added
	log.Printf("[%s] Authentication headers added:", a.name)
	log.Printf("  Date: %s", req.Header.Get("Date"))
	log.Printf("  Content-Type: %s", req.Header.Get("Content-Type"))
	log.Printf("  Content-Length: %s", req.Header.Get("Content-Length"))
	log.Printf("  X-Content-SHA256: %s", req.Header.Get("X-Content-SHA256"))
	log.Printf("  Authorization: %s", req.Header.Get("Authorization"))

	// Forward the authenticated request
	log.Printf("[%s] Forwarding authenticated request", a.name)
	a.next.ServeHTTP(rw, req)

	log.Printf("[%s] === OCI AUTH REQUEST END (success) ===", a.name)
}

// isOCIRequest determines if a request is destined for an OCI service.
// It checks if the host ends with ".oci.oraclecloud.com" which is the standard
// pattern for OCI service endpoints.
func (a *AuthPlugin) isOCIRequest(req *http.Request) bool {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Check if it's an OCI service endpoint
	isOCI := len(host) > 18 && host[len(host)-18:] == ".oci.oraclecloud.com"

	log.Printf("[%s] Host check: %s -> OCI request: %v", a.name, host, isOCI)
	return isOCI
}

// signRequest adds OCI authentication headers to the given HTTP request.
// It uses cached credentials when available or fetches fresh ones if needed.
func (a *AuthPlugin) signRequest(req *http.Request) (err error) {
	// Add panic recovery to prevent yaegi interpreter crashes
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("authentication panic recovered: %v", r)
		}
	}()

	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	keyProvider, err := internal.NewInstancePrincipalKeyProvider(nil)
	if err != nil {
		return fmt.Errorf("failed to create key provider: %w", err)
	}

	if keyProvider == nil {
		return fmt.Errorf("key provider is nil")
	}

	signer := internal.DefaultRequestSigner(keyProvider)
	if signer == nil {
		return fmt.Errorf("signer is nil")
	}

	if err := signer.Sign(req); err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	return nil
}

// CreateConfig creates the default plugin configuration.
// This function is required by Traefik's plugin system.
func CreateConfig() *Config {
	return &Config{}
}
