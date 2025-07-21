// Copyright (c) 2016, 2018, 2025, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

package internal

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
)

// httpGet makes a simple HTTP GET request to the given URL, expecting only "200 OK" status code.
// This is basically for the Instance Metadata Service.
func httpGet(dispatcher HTTPRequestDispatcher, url string) (body bytes.Buffer, statusCode int, err error) {
	var response *http.Response
	request, err := http.NewRequest(http.MethodGet, url, nil)

	request.Header.Add("Authorization", "Bearer Oracle")

	if response, err = dispatcher.Do(request); err != nil {
		return
	}

	statusCode = response.StatusCode
	// common.IfDebug(func() {
	// 	if dump, e := httputil.DumpResponse(response, true); e == nil {
	// 		common.Logf("Dump Response %v", string(dump))
	// 	} else {
	// 		common.Debugln(e)
	// 	}
	// })

	defer func() { _ = response.Body.Close() }()
	if _, err = body.ReadFrom(response.Body); err != nil {
		return
	}

	if statusCode != http.StatusOK {
		err = fmt.Errorf("HTTP Get failed: URL: %s, Status: %s, Message: %s",
			url, response.Status, body.String())
		return
	}

	return
}

func extractTenancyIDFromCertificate(cert *x509.Certificate) string {
	for _, nameAttr := range cert.Subject.Names {
		value := nameAttr.Value.(string)
		if strings.HasPrefix(value, "opc-tenant:") {
			return value[len("opc-tenant:"):]
		}
	}
	return ""
}

func fingerprint(certificate *x509.Certificate) string {
	fingerprint := sha256.Sum256(certificate.Raw)
	return colonSeparatedString(fingerprint)
}

func colonSeparatedString(fingerprint [sha256.Size]byte) string {
	spaceSeparated := fmt.Sprintf("% x", fingerprint)
	return strings.Replace(spaceSeparated, " ", ":", -1)
}
