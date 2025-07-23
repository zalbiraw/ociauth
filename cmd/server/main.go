package main

import (
	"context"
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

	// Create a backend handler for non-GET requests
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Backend received %s request: %s", r.Method, r.URL.String())

		// For non-GET requests, you can add custom logic here
		// For now, just return a simple response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"message": "Non-GET request processed", "method": "` + r.Method + `"}`)); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})

	// Create the OCI auth plugin with backend handler for non-GET requests
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
