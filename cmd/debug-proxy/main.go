package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func main() {
	// Get configuration from environment variables
	targetHost := os.Getenv("TARGET_HOST")
	if targetHost == "" {
		log.Fatal("TARGET_HOST environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Debug Reverse Proxy on port %s", port)
	log.Printf("Target host: %s", targetHost)

	// Parse target URL
	targetURL, err := url.Parse("https://" + targetHost)
	if err != nil {
		log.Fatalf("Invalid target host: %v", err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Add response logging by wrapping the ResponseWriter
	proxy.ModifyResponse = func(resp *http.Response) error {
		logProxyResponse(resp)
		return nil
	}

	// Wrap the proxy with logging
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logIncomingRequest(r)

		log.Printf("Proxying request to: https://%s%s", targetHost, r.URL.Path)

		// Let the reverse proxy handle the request
		proxy.ServeHTTP(w, r)
	})

	// Start the server
	if err := http.ListenAndServe(":"+port, proxyHandler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// logIncomingRequest logs comprehensive information about the incoming request
func logIncomingRequest(req *http.Request) {
	log.Printf("\n=== INCOMING REQUEST DEBUG ===")
	log.Printf("Method: %s", req.Method)
	log.Printf("URL: %s", req.URL.String())
	log.Printf("Host: %s", req.Host)
	log.Printf("Remote Address: %s", req.RemoteAddr)
	log.Printf("Protocol: %s", req.Proto)
	log.Printf("Content Length: %d", req.ContentLength)
	log.Printf("Transfer Encoding: %v", req.TransferEncoding)

	// Log URL components
	log.Printf("URL Components:")
	log.Printf("  Scheme: %s", req.URL.Scheme)
	log.Printf("  Host: %s", req.URL.Host)
	log.Printf("  Path: %s", req.URL.Path)
	log.Printf("  RawPath: %s", req.URL.RawPath)
	log.Printf("  RawQuery: %s", req.URL.RawQuery)
	log.Printf("  Fragment: %s", req.URL.Fragment)

	// Log query parameters
	if req.URL.RawQuery != "" {
		log.Printf("Query Parameters:")
		queryParams, _ := url.ParseQuery(req.URL.RawQuery)
		for key, values := range queryParams {
			for _, value := range values {
				log.Printf("  %s: %s", key, value)
			}
		}
	}

	// Log all headers
	log.Printf("Headers:")
	for key, values := range req.Header {
		for _, value := range values {
			log.Printf("  %s: %s", key, value)
		}
	}

	// Log request body (if present and not too large)
	if req.Body != nil && req.ContentLength > 0 && req.ContentLength <= 8192 { // Limit to 8KB
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			log.Printf("Request Body: [Error reading body: %v]", err)
		} else {
			// Replace the body with a new reader for the proxy request
			req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
			log.Printf("Request Body: %s", string(bodyBytes))
		}
	} else if req.ContentLength > 8192 {
		log.Printf("Request Body: [Body too large (%d bytes), not logged]", req.ContentLength)
	} else {
		log.Printf("Request Body: [Empty or no body]")
	}

	log.Printf("=== END INCOMING REQUEST DEBUG ===\n")
}

// logProxyResponse logs information about the response from the proxied server
func logProxyResponse(resp *http.Response) {
	log.Printf("\n=== PROXY RESPONSE DEBUG ===")
	log.Printf("Status Code: %d", resp.StatusCode)
	log.Printf("Status: %s", resp.Status)
	log.Printf("Protocol: %s", resp.Proto)
	log.Printf("Content Length: %d", resp.ContentLength)

	// Log response headers
	log.Printf("Response Headers:")
	for key, values := range resp.Header {
		for _, value := range values {
			log.Printf("  %s: %s", key, value)
		}
	}

	// Log response body (if not too large)
	if resp.Body != nil && resp.ContentLength > 0 && resp.ContentLength <= 8192 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Response Body: [Error reading body: %v]", err)
		} else {
			// Replace the body with a new reader so it can be read by the client
			resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
			log.Printf("Response Body: %s", string(bodyBytes))
		}
	} else if resp.ContentLength > 8192 {
		log.Printf("Response Body: [Body too large (%d bytes), not logged]", resp.ContentLength)
	} else {
		log.Printf("Response Body: [Empty or no body]")
	}

	log.Printf("=== END PROXY RESPONSE DEBUG ===\n")
}
