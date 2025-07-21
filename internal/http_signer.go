// Copyright (c) 2016, 2018, 2025, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

// Package auth provides utilities for signing HTTP requests according to OCI requirements.
//
//nolint:ireturn
package internal

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPRequestSigner the interface to sign a request.
type HTTPRequestSigner interface {
	Sign(r *http.Request) error
}

// KeyProvider interface that wraps information about the key's account owner.
type KeyProvider interface {
	PrivateRSAKey() (*rsa.PrivateKey, error)
	KeyID() (string, error)
}

const signerVersion = "1"

// SignerBodyHashPredicate a function that allows to disable/enable body hashing
// of requests and headers associated with body content.
type SignerBodyHashPredicate func(r *http.Request) bool

// ociRequestSigner implements the http-signatures-draft spec
// as described in https://tools.ietf.org/html/draft-cavage-http-signatures-08
type ociRequestSigner struct {
	KeyProvider    KeyProvider
	GenericHeaders []string
	BodyHeaders    []string
	ShouldHashBody SignerBodyHashPredicate
}

func getDefaultGenericHeaders() []string {
	return []string{"date", "(request-target)", "host"}
}

func getDefaultBodyHeaders() []string {
	return []string{"content-length", "content-type", "x-content-sha256"}
}

func getDefaultBodyHashPredicate() SignerBodyHashPredicate {
	return func(r *http.Request) bool {
		return r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch
	}
}

// DefaultRequestSigner creates a signer with default parameters.
func DefaultRequestSigner(provider KeyProvider) HTTPRequestSigner {
	return RequestSigner(provider, getDefaultGenericHeaders(), getDefaultBodyHeaders())
}

// RequestSigner creates a signer that utilizes the specified headers for signing
// and the default predicate for using the body of the request as part of the signature.
func RequestSigner(provider KeyProvider, genericHeaders, bodyHeaders []string) HTTPRequestSigner {
	if provider == nil {
		return nil
	}
	if genericHeaders == nil {
		genericHeaders = getDefaultGenericHeaders()
	}
	if bodyHeaders == nil {
		bodyHeaders = getDefaultBodyHeaders()
	}

	signer := ociRequestSigner{
		KeyProvider:    provider,
		GenericHeaders: genericHeaders,
		BodyHeaders:    bodyHeaders,
		ShouldHashBody: getDefaultBodyHashPredicate(),
	}
	return signer
}

func (signer ociRequestSigner) getSigningHeaders(r *http.Request) []string {
	var result []string
	result = append(result, signer.GenericHeaders...)

	if signer.ShouldHashBody(r) {
		result = append(result, signer.BodyHeaders...)
	}

	return result
}

func (signer ociRequestSigner) getSigningString(request *http.Request) string {
	signingHeaders := signer.getSigningHeaders(request)

	signingParts := make([]string, len(signingHeaders))
	for i, part := range signingHeaders {
		var value string
		part = strings.ToLower(part)
		switch part {
		case "(request-target)":
			value = getRequestTarget(request)
		case "host":
			value = request.URL.Host
			if len(value) == 0 {
				value = request.Host
			} else {
			}
		default:
			value = request.Header.Get(part)
		}
		signingParts[i] = fmt.Sprintf("%s: %s", part, value)
	}

	signingString := strings.Join(signingParts, "\n")
	return signingString
}

func getRequestTarget(request *http.Request) string {
	lowercaseMethod := strings.ToLower(request.Method)
	return fmt.Sprintf("%s %s", lowercaseMethod, request.URL.RequestURI())
}

func calculateHashOfBody(request *http.Request) error {
	var hash string
	hash, err := GetBodyHash(request)
	if err != nil {
		return err
	}
	request.Header.Set(requestHeaderXContentSHA256, hash)
	return nil
}

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
//
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func drainBody(b io.ReadCloser) (io.ReadCloser, io.ReadCloser, error) {
	if b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, http.NoBody, nil
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(b); err != nil {
		return nil, b, err
	}
	if err := b.Close(); err != nil {
		return nil, b, err
	}
	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func hashAndEncode(data []byte) string {
	hashedContent := sha256.Sum256(data)
	hash := base64.StdEncoding.EncodeToString(hashedContent[:])
	return hash
}

// GetBodyHash creates a base64 string from the hash of body the request.
func GetBodyHash(request *http.Request) (string, error) {
	if request.Body == nil {
		request.ContentLength = 0
		request.Header.Set(requestHeaderContentLength, fmt.Sprintf("%v", request.ContentLength))
		return hashAndEncode([]byte("")), nil
	}

	var data []byte
	var bReader io.Reader
	var err error
	bReader, request.Body, err = drainBody(request.Body)
	if err != nil {
		return "", fmt.Errorf("can not read body of request while calculating body hash: %w", err)
	}

	data, err = io.ReadAll(bReader)
	if err != nil {
		return "", fmt.Errorf("can not read body of request while calculating body hash: %w", err)
	}

	// Since the request can be coming from a binary body. Make an attempt to set the body length
	request.ContentLength = int64(len(data))
	request.Header.Set(requestHeaderContentLength, fmt.Sprintf("%v", request.ContentLength))

	hashString := hashAndEncode(data)
	return hashString, nil
}

func (signer ociRequestSigner) computeSignature(request *http.Request) (signature string, err error) {
	// Defensive checks for yaegi compatibility
	if signer.KeyProvider == nil {
		return "", fmt.Errorf("key provider is nil")
	}
	if request == nil {
		return "", fmt.Errorf("request is nil")
	}

	signingString := signer.getSigningString(request)
	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	hashed := hasher.Sum(nil)

	// Get private key with defensive handling
	privateKey, err := signer.KeyProvider.PrivateRSAKey()
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %w", err)
	}
	if privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	var unencodedSig []byte
	unencodedSig, e := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if e != nil {
		err = fmt.Errorf("can not compute signature while signing the request %s: ", e.Error())
		return
	}

	signature = base64.StdEncoding.EncodeToString(unencodedSig)
	return
}

// Sign signs the http request, by inspecting the necessary headers. Once signed
// the request will have the proper 'Authorization' header set, otherwise
// and error is returned.
func (signer ociRequestSigner) Sign(request *http.Request) (err error) {

	if signer.ShouldHashBody(request) {
		err = calculateHashOfBody(request)
		if err != nil {
			return
		}
	}

	var signature string
	if signature, err = signer.computeSignature(request); err != nil {
		return
	}

	signingHeaders := strings.Join(signer.getSigningHeaders(request), " ")

	var keyID string
	if keyID, err = signer.KeyProvider.KeyID(); err != nil {
		return
	}

	authValue := fmt.Sprintf("Signature version=\"%s\",headers=\"%s\",keyId=\"%s\",algorithm=\"rsa-sha256\",signature=\"%s\"",
		signerVersion, signingHeaders, keyID, signature)

	request.Header.Set(requestHeaderAuthorization, authValue)

	return
}
