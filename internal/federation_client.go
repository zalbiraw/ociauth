// Copyright (c) 2016, 2018, 2025, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

// Package auth provides supporting functions and structs for authentication
package internal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// federationClient is a client to retrieve the security token for an instance principal necessary to sign a request.
// It also provides the private key whose corresponding public key is used to retrieve the security token.
type federationClient interface {
	ClaimHolder
	PrivateKey() (*rsa.PrivateKey, error)
	SecurityToken() (string, error)
}

// ClaimHolder is implemented by any token interface that provides access to the security claims embedded in the token.
type ClaimHolder interface {
	GetClaim(key string) (interface{}, error)
}

type genericFederationClient struct {
	SessionKeySupplier   sessionKeySupplier
	RefreshSecurityToken func() (securityToken, error)

	securityToken securityToken
	mux           sync.Mutex
}

var _ federationClient = &genericFederationClient{}

func (c *genericFederationClient) PrivateKey() (*rsa.PrivateKey, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err := c.renewKeyAndSecurityTokenIfNotValid(); err != nil {
		return nil, err
	}
	return c.SessionKeySupplier.PrivateKey(), nil
}

func (c *genericFederationClient) SecurityToken() (token string, err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err = c.renewKeyAndSecurityTokenIfNotValid(); err != nil {
		return "", err
	}
	return c.securityToken.String(), nil
}

func (c *genericFederationClient) renewKeyAndSecurityTokenIfNotValid() (err error) {
	if c.securityToken == nil || !c.securityToken.Valid() {
		if err = c.renewKeyAndSecurityToken(); err != nil {
			return fmt.Errorf("failed to renew security token: %s", err.Error())
		}
	}
	return nil
}

func (c *genericFederationClient) renewKeyAndSecurityToken() (err error) {
	// common.Logf("Renewing keys for file based security token at: %v\n", time.Now().Format("15:04:05.000"))
	if err = c.SessionKeySupplier.Refresh(); err != nil {
		return fmt.Errorf("failed to refresh session key: %s", err.Error())
	}

	// common.Logf("Renewing security token at: %v\n", time.Now().Format("15:04:05.000"))
	if c.securityToken, err = c.RefreshSecurityToken(); err != nil {
		return fmt.Errorf("failed to refresh security token key: %s", err.Error())
	}
	// common.Logf("Security token renewed at: %v\n", time.Now().Format("15:04:05.000"))
	return nil
}

func (c *genericFederationClient) GetClaim(key string) (interface{}, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err := c.renewKeyAndSecurityTokenIfNotValid(); err != nil {
		return nil, err
	}
	return c.securityToken.GetClaim(key)
}

// x509FederationClient retrieves a security token from Auth service.
type x509FederationClient struct {
	tenancyID                         string
	sessionKeySupplier                sessionKeySupplier
	leafCertificateRetriever          x509CertificateRetriever
	intermediateCertificateRetrievers []x509CertificateRetriever
	securityToken                     securityToken
	authClient                        *BaseClient
	mux                               sync.Mutex
}

func newX509FederationClient(region Region, tenancyID string, leafCertificateRetriever x509CertificateRetriever, intermediateCertificateRetrievers []x509CertificateRetriever, modifier dispatcherModifier) (federationClient, error) {
	client := &x509FederationClient{
		tenancyID:                         tenancyID,
		leafCertificateRetriever:          leafCertificateRetriever,
		intermediateCertificateRetrievers: intermediateCertificateRetrievers,
	}
	client.sessionKeySupplier = newSessionKeySupplier()
	authClient := newAuthClient(region, client)

	var err error

	if authClient.HTTPClient, err = modifier.Modify(authClient.HTTPClient); err != nil {
		err = fmt.Errorf("failed to modify client: %s", err.Error())
		return nil, err
	}

	client.authClient = authClient
	return client, nil
}

var (
	genericHeaders = []string{"date", "(request-target)"} // "host" is not needed for the federation endpoint.  Don't ask me why.
	bodyHeaders    = []string{"content-length", "content-type", "x-content-sha256"}
)

func newAuthClient(region Region, provider KeyProvider) *BaseClient {
	signer := RequestSigner(provider, genericHeaders, bodyHeaders)
	client := DefaultBaseClientWithSigner(signer)
	if regionURL, ok := os.LookupEnv("OCI_SDK_AUTH_CLIENT_REGION_URL"); ok {
		client.Host = regionURL
	} else {
		client.Host = region.Endpoint("auth")
	}
	client.BasePath = "v1/x509"

	// if common.GlobalAuthClientCircuitBreakerSetting != nil {
	// 	client.Configuration.CircuitBreaker = common.NewCircuitBreaker(common.GlobalAuthClientCircuitBreakerSetting)
	// } else if !common.IsEnvVarFalse("OCI_SDK_AUTH_CLIENT_CIRCUIT_BREAKER_ENABLED") {
	// 	common.Logf("Configuring DefaultAuthClientCircuitBreakerSetting for federation client")
	// 	client.Configuration.CircuitBreaker = common.NewCircuitBreaker(common.DefaultAuthClientCircuitBreakerSetting())
	// }
	return &client
}

// For authClient to sign requests to X509 Federation Endpoint
func (c *x509FederationClient) KeyID() (string, error) {
	tenancy := c.tenancyID
	fingerprint := fingerprint(c.leafCertificateRetriever.Certificate())
	return fmt.Sprintf("%s/fed-x509-sha256/%s", tenancy, fingerprint), nil
}

// For authClient to sign requests to X509 Federation Endpoint
func (c *x509FederationClient) PrivateRSAKey() (*rsa.PrivateKey, error) {
	key := c.leafCertificateRetriever.PrivateKey()
	if key == nil {
		return nil, fmt.Errorf("can not read private key from leaf certificate. Likely an error in the metadata service")
	}

	return key, nil
}

func (c *x509FederationClient) PrivateKey() (*rsa.PrivateKey, error) {
	if c == nil {
		return nil, fmt.Errorf("federation client is nil")
	}
	if c.sessionKeySupplier == nil {
		return nil, fmt.Errorf("session key supplier is nil")
	}

	// Use mutex to protect concurrent access
	c.mux.Lock()
	defer c.mux.Unlock()

	// Defensive token renewal
	if err := c.renewSecurityTokenIfNotValid(); err != nil {
		return nil, err
	}

	// Get private key with explicit nil check
	privateKey := c.sessionKeySupplier.PrivateKey()
	if privateKey == nil {
		return nil, fmt.Errorf("session key supplier returned nil private key")
	}
	return privateKey, nil
}

func (c *x509FederationClient) SecurityToken() (token string, err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err = c.renewSecurityTokenIfNotValid(); err != nil {
		return "", err
	}
	return c.securityToken.String(), nil
}

func (c *x509FederationClient) renewSecurityTokenIfNotValid() (err error) {
	// Use more defensive checks to avoid yaegi reflection issues
	needsRenewal := false
	if c.securityToken == nil {
		needsRenewal = true
	} else {
		// Avoid direct interface method call that might trigger reflection
		if !c.securityToken.Valid() {
			needsRenewal = true
		}
	}

	if needsRenewal {
		if err = c.renewSecurityToken(); err != nil {
			return fmt.Errorf("failed to renew security token: %s", err.Error())
		}
	}
	return nil
}

func (c *x509FederationClient) renewSecurityToken() (err error) {
	// Check for nil federation client
	if c == nil {
		return fmt.Errorf("federation client is nil")
	}
	if c.sessionKeySupplier == nil {
		return fmt.Errorf("session key supplier is nil")
	}

	// Use defensive interface call to avoid yaegi reflection issues
	if err = c.sessionKeySupplier.Refresh(); err != nil {
		return fmt.Errorf("failed to refresh session key: %s", err.Error())
	}

	if err = c.leafCertificateRetriever.Refresh(); err != nil {
		return fmt.Errorf("failed to refresh leaf certificate: %s", err.Error())
	}

	updatedTenancyID := extractTenancyIDFromCertificate(c.leafCertificateRetriever.Certificate())
	if c.tenancyID != updatedTenancyID {
		err = fmt.Errorf("unexpected update of tenancy OCID in the leaf certificate. Previous tenancy: %s, Updated: %s", c.tenancyID, updatedTenancyID)
		return
	}

	for _, retriever := range c.intermediateCertificateRetrievers {
		if err = retriever.Refresh(); err != nil {
			return fmt.Errorf("failed to refresh intermediate certificate: %s", err.Error())
		}
	}

	// common.Logf("Renewing security token at: %v\n", time.Now().Format("15:04:05.000"))
	if c.securityToken, err = c.getSecurityToken(); err != nil {
		return fmt.Errorf("failed to get security token: %s", err.Error())
	}
	// common.Logf("Security token renewed at: %v\n", time.Now().Format("15:04:05.000"))

	return nil
}

func (c *x509FederationClient) getSecurityToken() (securityToken, error) {
	var err error
	var httpRequest http.Request
	var httpResponse *http.Response
	defer CloseBodyIfValid(httpResponse)

	for retry := 0; retry < 3; retry++ {
		request := c.makeX509FederationRequest()

		// Create HTTP request directly to avoid yaegi reflection issues with MakeDefaultHTTPRequestWithTaggedStruct
		httpRequest, err = c.createSimpleHTTPRequest(request)
		if err != nil {
			return nil, fmt.Errorf("failed to make http request: %s", err.Error())
		}

		if httpResponse, err = c.authClient.Call(context.Background(), &httpRequest); err == nil {
			break
		}
		// Don't retry on 4xx errors
		if httpResponse != nil && httpResponse.StatusCode >= 400 && httpResponse.StatusCode <= 499 {
			return nil, fmt.Errorf("error %s returned by auth service: %s", httpResponse.Status, err.Error())
		}
		nextDuration := time.Duration(1000.0*(math.Pow(2.0, float64(retry)))) * time.Millisecond
		time.Sleep(nextDuration)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to call: %s", err.Error())
	}

	response := x509FederationResponse{}
	if err = UnmarshalResponse(httpResponse, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the response: %s", err.Error())
	}

	return newPrincipalToken(response.Token.Token)
}

func (c *x509FederationClient) GetClaim(key string) (interface{}, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if err := c.renewSecurityTokenIfNotValid(); err != nil {
		return nil, err
	}
	return c.securityToken.GetClaim(key)
}

type x509FederationRequest struct {
	X509FederationDetails `contributesTo:"body"`
}

// X509FederationDetails x509 federation details
type X509FederationDetails struct {
	Certificate              string   `mandatory:"true" json:"certificate,omitempty"`
	PublicKey                string   `mandatory:"true" json:"publicKey,omitempty"`
	IntermediateCertificates []string `mandatory:"false" json:"intermediateCertificates,omitempty"`
	FingerprintAlgorithm     string   `mandatory:"false" json:"fingerprintAlgorithm,omitempty"`
}

type x509FederationResponse struct {
	Token `presentIn:"body"`
}

// Token token
type Token struct {
	Token string `mandatory:"true" json:"token,omitempty"`
}

func (c *x509FederationClient) makeX509FederationRequest() *x509FederationRequest {
	// Defensive interface method call to avoid yaegi reflection panics
	var certificateBytes []byte
	if c.leafCertificateRetriever != nil {
		certificateBytes = c.leafCertificateRetriever.CertificatePemRaw()
	}
	certificate := c.sanitizeCertificateString(string(certificateBytes))
	var publicKeyBytes []byte
	if c.sessionKeySupplier != nil {
		publicKeyBytes = c.sessionKeySupplier.PublicKeyPemRaw()
	}
	publicKey := c.sanitizeCertificateString(string(publicKeyBytes))
	var intermediateCertificates []string
	for _, retriever := range c.intermediateCertificateRetrievers {
		if retriever != nil {
			certBytes := retriever.CertificatePemRaw()
			intermediateCertificates = append(intermediateCertificates, c.sanitizeCertificateString(string(certBytes)))
		}
	}

	details := X509FederationDetails{
		Certificate:              certificate,
		PublicKey:                publicKey,
		IntermediateCertificates: intermediateCertificates,
		FingerprintAlgorithm:     "SHA256",
	}
	return &x509FederationRequest{details}
}

// createSimpleHTTPRequest creates an HTTP request without using reflection to avoid yaegi issues
func (c *x509FederationClient) createSimpleHTTPRequest(request *x509FederationRequest) (http.Request, error) {
	// Marshal the request to JSON manually
	reqBody, err := json.Marshal(request.X509FederationDetails)
	if err != nil {
		return http.Request{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create HTTP request manually without reflection
	httpRequest := http.Request{
		Method:        http.MethodPost,
		URL:           &url.URL{},
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(reqBody)),
		ContentLength: int64(len(reqBody)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
	}

	// Set required headers
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Content-Length", strconv.FormatInt(httpRequest.ContentLength, 10))
	httpRequest.Header.Set("Accept", "*/*")
	httpRequest.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	return httpRequest, nil
}

func (c *x509FederationClient) sanitizeCertificateString(certString string) string {
	certString = strings.Replace(certString, "-----BEGIN CERTIFICATE-----", "", -1)
	certString = strings.Replace(certString, "-----END CERTIFICATE-----", "", -1)
	certString = strings.Replace(certString, "-----BEGIN PUBLIC KEY-----", "", -1)
	certString = strings.Replace(certString, "-----END PUBLIC KEY-----", "", -1)
	certString = strings.Replace(certString, "\n", "", -1)
	return certString
}

// sessionKeySupplier provides an RSA keypair which can be re-generated by calling Refresh().
type sessionKeySupplier interface {
	Refresh() error
	PrivateKey() *rsa.PrivateKey
	PublicKeyPemRaw() []byte
}

// inMemorySessionKeySupplier implements sessionKeySupplier to vend an RSA keypair.
// Refresh() generates a new RSA keypair with a random source, and keeps it in memory.
//
// inMemorySessionKeySupplier is not thread-safe.
type inMemorySessionKeySupplier struct {
	keySize         int
	privateKey      *rsa.PrivateKey
	publicKeyPemRaw []byte
}

// newSessionKeySupplier creates and returns a sessionKeySupplier instance which generates key pairs of size 2048.
func newSessionKeySupplier() sessionKeySupplier {
	return &inMemorySessionKeySupplier{keySize: 2048}
}

// Refresh() is failure atomic, i.e., PrivateKey() and PublicKeyPemRaw() would return their previous values
// if Refresh() fails.
func (s *inMemorySessionKeySupplier) Refresh() (err error) {
	// Check if supplier is nil to avoid reflection panics
	if s == nil {
		return fmt.Errorf("session key supplier is nil")
	}

	// Generate key with explicit error handling
	var privateKey *rsa.PrivateKey
	privateKey, err = rsa.GenerateKey(rand.Reader, s.keySize)
	if err != nil {
		return fmt.Errorf("failed to generate a new keypair: %s", err)
	}
	if privateKey == nil {
		return fmt.Errorf("generated private key is nil")
	}

	// Marshal public key with explicit checks
	publicKeyInterface := privateKey.Public()
	if publicKeyInterface == nil {
		return fmt.Errorf("public key is nil")
	}

	var publicKeyAsnBytes []byte
	if publicKeyAsnBytes, err = x509.MarshalPKIXPublicKey(publicKeyInterface); err != nil {
		return fmt.Errorf("failed to marshal the public part of the new keypair: %s", err.Error())
	}

	// Create PEM block with explicit struct literal
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyAsnBytes,
	}
	publicKeyPemRaw := pem.EncodeToMemory(pemBlock)
	if publicKeyPemRaw == nil {
		return fmt.Errorf("failed to encode public key to PEM")
	}

	// Update fields atomically
	s.privateKey = privateKey
	s.publicKeyPemRaw = publicKeyPemRaw
	return nil
}

func (s *inMemorySessionKeySupplier) PrivateKey() *rsa.PrivateKey {
	// Defensive nil checks to avoid yaegi reflection panics
	if s == nil {
		return nil
	}
	if s.privateKey == nil {
		return nil
	}

	// Return the original pointer directly to avoid yaegi reflection issues with struct copying
	return s.privateKey
}

func (s *inMemorySessionKeySupplier) PublicKeyPemRaw() []byte {
	if s.publicKeyPemRaw == nil {
		return nil
	}

	c := make([]byte, len(s.publicKeyPemRaw))
	copy(c, s.publicKeyPemRaw)
	return c
}

type securityToken interface {
	fmt.Stringer
	Valid() bool

	ClaimHolder
}

type principalToken struct {
	tokenString string
	jwtToken    *jwtToken
}

func newPrincipalToken(tokenString string) (newToken securityToken, err error) {
	var jwtToken *jwtToken
	if jwtToken, err = parseJwt(tokenString); err != nil {
		return nil, fmt.Errorf("failed to parse the token string \"%s\": %s", tokenString, err.Error())
	}
	return &principalToken{tokenString, jwtToken}, nil
}

func (t *principalToken) String() string {
	return t.tokenString
}

func (t *principalToken) Valid() bool {
	return !t.jwtToken.expired()
}

var (
	// ErrNoSuchClaim is returned when a token does not hold the claim sought
	ErrNoSuchClaim = errors.New("no such claim")
)

func (t *principalToken) GetClaim(key string) (interface{}, error) {
	if value, ok := t.jwtToken.payload[key]; ok {
		return value, nil
	}
	return nil, ErrNoSuchClaim
}
