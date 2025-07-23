package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/zalbiraw/ociauth"
)

func main() {
	// Get configuration from environment variables
	region := os.Getenv("OCI_REGION")
	if region == "" {
		region = "us-chicago-1"
	}

	serviceName := os.Getenv("OCI_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "generativeai"
	}

	authType := os.Getenv("OCI_AUTH_TYPE")
	if authType == "" {
		authType = "instance_principal"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create plugin configuration
	config := &ociauth.Config{
		AuthType:    authType,
		ServiceName: serviceName,
		Region:      region,
	}

	// Create a backend handler that forwards to actual OCI API and logs responses
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Backend received request: %s %s", r.Method, r.URL.String())

		// Create HTTP client for actual OCI call
		client := &http.Client{}

		// Create the actual request to OCI
		ociReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			log.Printf("Failed to create OCI request: %v", err)
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}

		// Copy headers from authenticated request
		for key, values := range r.Header {
			for _, value := range values {
				ociReq.Header.Add(key, value)
			}
		}

		// Make the actual call to OCI
		resp, err := client.Do(ociReq)
		if err != nil {
			log.Printf("OCI API call failed: %v", err)
			http.Error(w, "OCI API call failed", http.StatusInternalServerError)
			return
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				log.Printf("Failed to close response body: %v", closeErr)
			}
		}()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read OCI response: %v", err)
			http.Error(w, "Failed to read response", http.StatusInternalServerError)
			return
		}

		// Log the actual OCI API response
		log.Printf("OCI API Response Status: %d", resp.StatusCode)
		log.Printf("OCI API Response Headers: %v", resp.Header)
		log.Printf("OCI API Response Body: %s", string(body))

		// Forward response to client
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := w.Write(body); err != nil {
			log.Printf("Failed to write response body: %v", err)
		}
	})

	// Create the OCI auth plugin
	authHandler, err := ociauth.New(context.Background(), backendHandler, config, "ociauth-server")
	if err != nil {
		log.Fatalf("Failed to create OCI auth plugin: %v", err)
	}

	log.Printf("Starting OCI Auth server on port %s", port)
	log.Printf("Configuration: AuthType=%s, ServiceName=%s, Region=%s", authType, serviceName, region)

	// Start the server
	if err := http.ListenAndServe(":"+port, authHandler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
