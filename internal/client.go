// Copyright (c) 2016, 2018, 2025, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

// Package auth provides supporting functions and structs used by service packages
package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// requestHeaderAccept The key for passing a header to indicate Accept
	requestHeaderAccept = "Accept"

	// requestHeaderAuthorization The key for passing a header to indicate Authorization
	requestHeaderAuthorization = "Authorization"

	// requestHeaderContentLength The key for passing a header to indicate Content Length
	requestHeaderContentLength = "Content-Length"

	// requestHeaderContentType The key for passing a header to indicate Content Type
	requestHeaderContentType = "Content-Type"

	// requestHeaderDate The key for passing a header to indicate Date
	requestHeaderDate = "Date"

	// requestHeaderOpcClientInfo The key for passing a header to indicate OPC Client Info
	requestHeaderOpcClientInfo = "opc-client-info"

	// requestHeaderOpcRequestID The key for unique Oracle-assigned identifier for the request.
	requestHeaderOpcRequestID = "opc-request-id"

	// requestHeaderOpcClientRequestID The key for unique Oracle-assigned identifier for the request.
	requestHeaderOpcClientRequestID = "opc-client-request-id"

	// requestHeaderUserAgent The key for passing a header to indicate User Agent
	requestHeaderUserAgent = "User-Agent"

	// requestHeaderXContentSHA256 The key for passing a header to indicate SHA256 hash
	requestHeaderXContentSHA256 = "X-Content-SHA256"

	// private constants
	defaultScheme    = "https"
	defaultSDKMarker = "Oracle-GoSDK"

	defaultUserAgentTemplate = "%s/%s (%s/%s; go/%s)" // SDK/SDKVersion (OS/OSVersion; Lang/LangVersion)
	// http.Client.Timeout includes Dial, TLSHandshake, Request, Response header and body
	defaultTimeout = 60 * time.Second

	maxBodyLenForDebug = 1024 * 1000

	// appendUserAgentEnv The key for retrieving append user agent value from env var
	appendUserAgentEnv = "OCI_SDK_APPEND_USER_AGENT"

	// ociDefaultRefreshIntervalForCustomCerts is the env var for overriding the defaultRefreshIntervalForCustomCerts.
	// The value represents the refresh interval in minutes and has a higher precedence than defaultRefreshIntervalForCustomCerts
	// but has a lower precedence then the refresh interval configured via OciGlobalRefreshIntervalForCustomCerts
	// If the value is negative, then it is assumed that this property is not configured
	// if the value is Zero, then the refresh of custom certs will be disabled
	ociDefaultRefreshIntervalForCustomCerts = "OCI_DEFAULT_REFRESH_INTERVAL_FOR_CUSTOM_CERTS"

	// ociDefaultCertsPath is the env var for the path to the SSL cert file
	ociDefaultCertsPath = "OCI_DEFAULT_CERTS_PATH"

	// ociDefaultClientCertsPath is the env var for the path to the custom client cert
	ociDefaultClientCertsPath = "OCI_DEFAULT_CLIENT_CERTS_PATH"

	// ociDefaultClientCertsPrivateKeyPath is the env var for the path to the custom client cert private key
	ociDefaultClientCertsPrivateKeyPath = "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"

	// maxAttemptsForRefreshableRetry is the number of retry when 401 happened on a refreshable auth type
	maxAttemptsForRefreshableRetry = 3

	// defaultRefreshIntervalForCustomCerts is the default refresh interval in minutes
	defaultRefreshIntervalForCustomCerts = 30
)

// OciGlobalRefreshIntervalForCustomCerts is the global policy for overriding the refresh interval in minutes.
// This variable has a higher precedence than the env variable OCI_DEFAULT_REFRESH_INTERVAL_FOR_CUSTOM_CERTS
// and the defaultRefreshIntervalForCustomCerts values.
// If the value is negative, then it is assumed that this property is not configured
// if the value is Zero, then the refresh of custom certs will be disabled
var OciGlobalRefreshIntervalForCustomCerts int = -1

// RequestInterceptor function used to customize the request before calling the underlying service
type RequestInterceptor func(*http.Request) error

// HTTPRequestDispatcher wraps the execution of a http request, it is generally implemented by
// http.Client.Do, but can be customized for testing
type HTTPRequestDispatcher interface {
	Do(req *http.Request) (*http.Response, error)
}

// BaseClient struct implements all basic operations to call oci web services.
type BaseClient struct {
	// HTTPClient performs the http network operations
	HTTPClient HTTPRequestDispatcher

	// Signer performs auth operation
	Signer HTTPRequestSigner

	// A request interceptor can be used to customize the request before signing and dispatching
	Interceptor RequestInterceptor

	// The host of the service
	Host string

	// The user agent
	UserAgent string

	// Base path for all operations of this client
	BasePath string
}

func defaultUserAgent() string {
	userAgent := fmt.Sprintf(defaultUserAgentTemplate, defaultSDKMarker, Version(), runtime.GOOS, runtime.GOARCH, runtime.Version())
	appendUA := os.Getenv(appendUserAgentEnv)
	if appendUA != "" {
		userAgent = fmt.Sprintf("%s %s", userAgent, appendUA)
	}
	return userAgent
}

var clientCounter int64

func getNextSeed() int64 {
	newCounterValue := atomic.AddInt64(&clientCounter, 1)
	return newCounterValue + time.Now().UnixNano()
}

func newBaseClient(signer HTTPRequestSigner, dispatcher HTTPRequestDispatcher) BaseClient {
	rand.Seed(getNextSeed())

	baseClient := BaseClient{
		UserAgent:   defaultUserAgent(),
		Interceptor: nil,
		Signer:      signer,
		HTTPClient:  dispatcher,
	}

	return baseClient
}

func createOciTransport() http.RoundTripper {
	refreshInterval := getCustomCertRefreshInterval()
	if refreshInterval <= 0 {
		// Debug("Custom cert refresh has been disabled")
	}
	return &OciHTTPTransportWrapper{
		RefreshRate:       time.Duration(refreshInterval) * time.Minute,
		TLSConfigProvider: GetTLSConfigTemplateForTransport(),
	}
}

func defaultHTTPDispatcher() http.Client {
	var httpClient http.Client
	tp := createOciTransport()
	httpClient = http.Client{
		Timeout:   defaultTimeout,
		Transport: tp,
	}
	return httpClient
}

func defaultBaseClient(provider KeyProvider) BaseClient {
	dispatcher := defaultHTTPDispatcher()
	signer := DefaultRequestSigner(provider)
	return newBaseClient(signer, &dispatcher)
}

// DefaultBaseClientWithSigner creates a default base client with a given signer
func DefaultBaseClientWithSigner(signer HTTPRequestSigner) BaseClient {
	dispatcher := defaultHTTPDispatcher()
	return newBaseClient(signer, &dispatcher)
}

// setRawPath sets the Path and RawPath fields of the URL based on the provided
// escaped path p. It maintains the invariant that RawPath is only specified
// when it differs from the default encoding of the path.
// For example:
// - setPath("/foo/bar")   will set Path="/foo/bar" and RawPath=""
// - setPath("/foo%2fbar") will set Path="/foo/bar" and RawPath="/foo%2fbar"
func setRawPath(u *url.URL) error {
	oldPath := u.Path
	path, err := url.PathUnescape(u.Path)
	if err != nil {
		return err
	}
	u.Path = path
	if escp := u.EscapedPath(); oldPath == escp {
		// Default encoding is fine.
		u.RawPath = ""
	} else {
		u.RawPath = oldPath
	}
	return nil
}

func (client *BaseClient) prepareRequest(request *http.Request) (err error) {
	if client.UserAgent == "" {
		client.UserAgent = defaultUserAgent()
	}

	if request.Header == nil {
		request.Header = http.Header{}
	}
	request.Header.Set(requestHeaderUserAgent, client.UserAgent)
	request.Header.Set(requestHeaderDate, time.Now().UTC().Format(http.TimeFormat))

	if !strings.Contains(client.Host, "http") &&
		!strings.Contains(client.Host, "https") {
		client.Host = fmt.Sprintf("%s://%s", defaultScheme, client.Host)
	}

	clientURL, err := url.Parse(client.Host)
	if err != nil {
		return fmt.Errorf("host is invalid. %s", err.Error())
	}
	request.URL.Host = clientURL.Host
	request.URL.Scheme = clientURL.Scheme
	currentPath := request.URL.Path
	if !strings.Contains(currentPath, fmt.Sprintf("/%s", client.BasePath)) {
		request.URL.Path = path.Clean(fmt.Sprintf("/%s/%s", client.BasePath, currentPath))
		err := setRawPath(request.URL)
		if err != nil {
			return err
		}
	}
	return
}

func (client BaseClient) intercept(request *http.Request) (err error) {
	if client.Interceptor != nil {
		err = client.Interceptor(request)
	}
	return
}

// checkForSuccessfulResponse checks if the response is successful
// If Error Code is 4XX/5XX and debug level is set to info, will log the request and response
func checkForSuccessfulResponse(res *http.Response, requestBody *io.ReadCloser) error {
	familyStatusCode := res.StatusCode / 100
	if familyStatusCode == 4 || familyStatusCode == 5 {
		// IfInfo(func() {
		// 	// If debug level is set to verbose, the request and request body will be dumped and logged under debug level, this is to avoid duplicate logging
		// 	if defaultLogger.LogLevel() < verboseLogging {
		// 		logRequest(res.Request, Logf, noLogging)
		// 		if requestBody != nil && *requestBody != http.NoBody {
		// 			bodyContent, _ := ioutil.ReadAll(*requestBody)
		// 			Logf("Dump Request Body: \n%s", string(bodyContent))
		// 		}
		// 	}
		// 	logResponse(res, Logf, infoLogging)
		// })
		return nil
	}
	// IfDebug(func() {
	// 	logResponse(res, Debugf, verboseLogging)
	// })
	return nil
}

// func logRequest(request *http.Request, fn func(format string, v ...interface{}), bodyLoggingLevel int) {
// 	if request == nil {
// 		return
// 	}
// 	dumpBody := true
// 	if checkBodyLengthExceedLimit(request.ContentLength) {
// 		fn("not dumping body too big\n")
// 		dumpBody = false
// 	}

// 	dumpBody = dumpBody && defaultLogger.LogLevel() >= bodyLoggingLevel && bodyLoggingLevel != noLogging
// 	if dump, e := httputil.DumpRequestOut(request, dumpBody); e == nil {
// 		fn("Dump Request %s", string(dump))
// 	} else {
// 		fn("%v\n", e)
// 	}
// }

// func logResponse(response *http.Response, fn func(format string, v ...interface{}), bodyLoggingLevel int) {
// 	if response == nil {
// 		return
// 	}
// 	dumpBody := true
// 	if checkBodyLengthExceedLimit(response.ContentLength) {
// 		fn("not dumping body too big\n")
// 		dumpBody = false
// 	}
// 	dumpBody = dumpBody && defaultLogger.LogLevel() >= bodyLoggingLevel && bodyLoggingLevel != noLogging
// 	if dump, e := httputil.DumpResponse(response, dumpBody); e == nil {
// 		fn("Dump Response %s", string(dump))
// 	} else {
// 		fn("%v\n", e)
// 	}
// }

func checkBodyLengthExceedLimit(contentLength int64) bool {
	return contentLength > maxBodyLenForDebug
}

// OCIRequest is any request made to an OCI service.
type OCIRequest interface {
	// HTTPRequest assembles an HTTP request.
	HTTPRequest(method, path string, binaryRequestBody *OCIReadSeekCloser, extraHeaders map[string]string) (http.Request, error)
}

// OCIReadSeekCloser is a thread-safe io.ReadSeekCloser to prevent racing with retrying binary requests
type OCIReadSeekCloser struct {
	rc       io.ReadCloser
	lock     sync.Mutex
	isClosed bool
}

// NewOCIReadSeekCloser constructs OCIReadSeekCloser, the only input is binary request body
func NewOCIReadSeekCloser(rc io.ReadCloser) *OCIReadSeekCloser {
	rsc := OCIReadSeekCloser{}
	rsc.rc = rc
	return &rsc
}

// Seek is a thread-safe operation, it implements io.seek() interface, if the original request body implements io.seek()
// interface, or implements "well-known" data type like os.File, io.SectionReader, or wrapped by ioutil.NopCloser can be supported
func (rsc *OCIReadSeekCloser) Seek(offset int64, whence int) (int64, error) {
	rsc.lock.Lock()
	defer rsc.lock.Unlock()

	if _, ok := rsc.rc.(io.Seeker); ok {
		return rsc.rc.(io.Seeker).Seek(offset, whence)
	}
	// once the binary request body is wrapped with ioutil.NopCloser:
	if isNopCloser(rsc.rc) {
		rcValue := reflect.ValueOf(rsc.rc)
		if rcValue.IsValid() && rcValue.NumField() > 0 {
			field := rcValue.Field(0)
			unwrappedInterface := field.Interface()
			if _, ok := unwrappedInterface.(io.Seeker); ok {
				return unwrappedInterface.(io.Seeker).Seek(offset, whence)
			}
		}
	}
	return 0, fmt.Errorf("current binary request body type is not seekable, if want to use retry feature, please make sure the request body implements seek() method")
}

// Close is a thread-safe operation, it closes the instance of the OCIReadSeekCloser's access to the underlying io.ReadCloser.
func (rsc *OCIReadSeekCloser) Close() error {
	rsc.lock.Lock()
	defer rsc.lock.Unlock()
	rsc.isClosed = true
	return nil
}

// Read is a thread-safe operation, it implements io.Read() interface
func (rsc *OCIReadSeekCloser) Read(p []byte) (n int, err error) {
	rsc.lock.Lock()
	defer rsc.lock.Unlock()

	if rsc.isClosed {
		return 0, io.EOF
	}

	return rsc.rc.Read(p)
}

// Seekable is used for check if the binary request body can be seek or no
func (rsc *OCIReadSeekCloser) Seekable() bool {
	if rsc == nil {
		return false
	}
	if _, ok := rsc.rc.(io.Seeker); ok {
		return true
	}
	// once the binary request body is wrapped with ioutil.NopCloser:
	if isNopCloser(rsc.rc) {
		rcValue := reflect.ValueOf(rsc.rc)
		field := rcValue.Field(0)
		intf := field.Interface()
		if _, ok := intf.(io.Seeker); ok {
			return true
		}
	}
	return false
}

// ClientCallDetails a set of settings used by the a single Call operation of the http Client
type ClientCallDetails struct {
	Signer HTTPRequestSigner
}

// Call executes the http request with the given context
func (client BaseClient) Call(ctx context.Context, request *http.Request) (response *http.Response, err error) {
	if client.IsRefreshableAuthType() {
		return client.RefreshableTokenWrappedCallWithDetails(ctx, request, ClientCallDetails{Signer: client.Signer})
	}
	return client.CallWithDetails(ctx, request, ClientCallDetails{Signer: client.Signer})
}

// RefreshableTokenWrappedCallWithDetails wraps the CallWithDetails with retry on 401 for Refreshable Toekn (Instance Principal, Resource Principal etc.)
// This is to intimitate the race condition on refresh
func (client BaseClient) RefreshableTokenWrappedCallWithDetails(ctx context.Context, request *http.Request, details ClientCallDetails) (response *http.Response, err error) {
	for i := 0; i < maxAttemptsForRefreshableRetry; i++ {
		response, err = client.CallWithDetails(ctx, request, ClientCallDetails{Signer: client.Signer})
		if response != nil && response.StatusCode != 401 {
			return response, err
		}
		time.Sleep(1 * time.Second)
	}
	return
}

// CallWithDetails executes the http request, the given context using details specified in the parameters, this function
// provides a way to override some settings present in the client
func (client BaseClient) CallWithDetails(ctx context.Context, request *http.Request, details ClientCallDetails) (response *http.Response, err error) {
	// Debugln("Attempting to call downstream service")
	request = request.WithContext(ctx)
	err = client.prepareRequest(request)
	if err != nil {
		return
	}
	// Intercept
	err = client.intercept(request)
	if err != nil {
		return
	}
	// Sign the request
	err = details.Signer.Sign(request)
	if err != nil {
		return
	}

	// Execute the http request
	// if ociGoBreaker := client.Configuration.CircuitBreaker; ociGoBreaker != nil {
	// 	resp, cbErr := ociGoBreaker.Cb.Execute(func() (interface{}, error) {
	// 		return client.httpDo(request)
	// 	})
	// 	if httpResp, ok := resp.(*http.Response); ok {
	// 		if httpResp != nil && httpResp.StatusCode != 200 {
	// 			if failure, ok := IsServiceError(cbErr); ok {
	// 				ociGoBreaker.AddToHistory(resp.(*http.Response), failure)
	// 			}
	// 		}
	// 	}
	// 	if cbErr != nil && IsCircuitBreakerError(cbErr) {
	// 		cbErr = getCircuitBreakerError(request, cbErr, ociGoBreaker)
	// 	}
	// 	if _, ok := resp.(*http.Response); !ok {
	// 		return nil, cbErr
	// 	}
	// 	return resp.(*http.Response), cbErr
	// }
	return client.httpDo(request)
}

// RefreshableConfigurationProvider the interface to identity if the config provider is refreshable
type RefreshableConfigurationProvider interface {
	Refreshable() bool
}

// IsRefreshableAuthType validates if a signer is from a refreshable config provider
func (client BaseClient) IsRefreshableAuthType() bool {
	if client.Signer == nil {
		return false
	}
	if signer, ok := client.Signer.(ociRequestSigner); ok {
		if signer.KeyProvider == nil {
			return false
		}
		if provider, ok := signer.KeyProvider.(RefreshableConfigurationProvider); ok {
			return provider.Refreshable()
		}
	}
	return false
}

func (client BaseClient) httpDo(request *http.Request) (response *http.Response, err error) {

	// Copy request body and save for logging
	dumpRequestBody := io.NopCloser(bytes.NewBuffer(nil))
	if request.Body != nil && !checkBodyLengthExceedLimit(request.ContentLength) {
		if dumpRequestBody, request.Body, err = drainBody(request.Body); err != nil {
			dumpRequestBody = io.NopCloser(bytes.NewBuffer(nil))
		}
	}
	// IfDebug(func() {
	// 	logRequest(request, Debugf, verboseLogging)
	// })

	// Execute the http request
	response, err = client.HTTPClient.Do(request)

	if err != nil {
		// 	IfInfo(func() {
		// 		Logf("%v\n", err)
		// 	})
		// 	return response, err
	}

	err = checkForSuccessfulResponse(response, &dumpRequestBody)
	return response, err
}

// CloseBodyIfValid closes the body of an http response if the response and the body are valid
func CloseBodyIfValid(httpResponse *http.Response) {
	if httpResponse != nil && httpResponse.Body != nil {
		if httpResponse.Header != nil && strings.ToLower(httpResponse.Header.Get("content-type")) == "text/event-stream" {
			return
		}
		_ = httpResponse.Body.Close()
	}
}

func getCustomCertRefreshInterval() int {
	if OciGlobalRefreshIntervalForCustomCerts >= 0 {
		// Debugf("Setting refresh interval as %d for custom certs via OciGlobalRefreshIntervalForCustomCerts", OciGlobalRefreshIntervalForCustomCerts)
		return OciGlobalRefreshIntervalForCustomCerts
	}
	if refreshIntervalValue, ok := os.LookupEnv(ociDefaultRefreshIntervalForCustomCerts); ok {
		refreshInterval, err := strconv.Atoi(refreshIntervalValue)
		if err != nil || refreshInterval < 0 {
			// Debugf("The environment variable %s is not a valid int or is a negative value, skipping this configuration", ociDefaultRefreshIntervalForCustomCerts)
		} else {
			// Debugf("Setting refresh interval as %d for custom certs via the env variable %s", refreshInterval, ociDefaultRefreshIntervalForCustomCerts)
			return refreshInterval
		}
	}
	// Debugf("Setting the default refresh interval %d for custom certs", defaultRefreshIntervalForCustomCerts)
	return defaultRefreshIntervalForCustomCerts
}
