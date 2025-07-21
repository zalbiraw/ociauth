// Copyright (c) 2016, 2018, 2025, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

//lint:file-ignore SA1019 older versions of staticcheck (those compatible with Golang 1.17) falsely flag x509.IsEncryptedPEMBlock and x509.DecryptPEMBlock.

package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/textproto"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// SDKTime a struct that parses/renders to/from json using RFC339 date-time information
type SDKTime struct {
	time.Time
}

// SDKDate a struct that parses/renders to/from json using only date information
type SDKDate struct {
	//Date date information
	Date time.Time
}

func sdkTimeFromTime(t time.Time) SDKTime {
	return SDKTime{t}
}

func sdkDateFromTime(t time.Time) SDKDate {
	return SDKDate{Date: t}
}

func formatTime(t SDKTime) string {
	return t.Format(sdkTimeFormat)
}

func formatDate(t SDKDate) string {
	return t.Date.Format(sdkDateFormat)
}

func now() *SDKTime {
	t := SDKTime{time.Now()}
	return &t
}

var timeType = reflect.TypeOf(SDKTime{})
var timeTypePtr = reflect.TypeOf(&SDKTime{})

var sdkDateType = reflect.TypeOf(SDKDate{})
var sdkDateTypePtr = reflect.TypeOf(&SDKDate{})

// Formats for sdk supported time representations
const sdkTimeFormat = time.RFC3339Nano
const rfc1123OptionalLeadingDigitsInDay = "Mon, _2 Jan 2006 15:04:05 MST"
const sdkDateFormat = "2006-01-02"

func tryParsingTimeWithValidFormatsForHeaders(data []byte, headerName string) (t time.Time, err error) {
	header := strings.ToLower(headerName)
	switch header {
	case "lastmodified", "date":
		t, err = tryParsing(data, time.RFC3339Nano, time.RFC3339, time.RFC1123, rfc1123OptionalLeadingDigitsInDay, time.RFC850, time.ANSIC)
		return
	default: //By default we parse with RFC3339
		t, err = time.Parse(sdkTimeFormat, string(data))
		return
	}
}

func tryParsing(data []byte, layouts ...string) (tm time.Time, err error) {
	datestring := string(data)
	for _, l := range layouts {
		tm, err = time.Parse(l, datestring)
		if err == nil {
			return
		}
	}
	err = fmt.Errorf("could not parse time: %s with formats: %s", datestring, layouts[:])
	return
}

// PrivateKeyFromBytes is a helper function that will produce a RSA private
// key from bytes. This function is deprecated in favour of PrivateKeyFromBytesWithPassword
// Deprecated
func PrivateKeyFromBytes(pemData []byte, password *string) (key *rsa.PrivateKey, e error) {
	if password == nil {
		return PrivateKeyFromBytesWithPassword(pemData, nil)
	}

	return PrivateKeyFromBytesWithPassword(pemData, []byte(*password))
}

// PrivateKeyFromBytesWithPassword is a helper function that will produce a RSA private
// key from bytes and a password.
func PrivateKeyFromBytesWithPassword(pemData, password []byte) (key *rsa.PrivateKey, e error) {
	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		e = fmt.Errorf("PEM data was not found in buffer")
		return
	}

	decrypted := pemBlock.Bytes
	// Support for encrypted PKCS8 format, this format can not be handled by x509.IsEncryptedPEMBlock func
	// if key, e = pkcs8.ParsePKCS8PrivateKeyRSA(pemBlock.Bytes, password); key != nil {
	// 	return
	// }
	// if pemBlock.Type == "ENCRYPTED PRIVATE KEY" {
	// 	return pkcs8.ParsePKCS8PrivateKeyRSA(pemData, password)
	// }
	if x509.IsEncryptedPEMBlock(pemBlock) {
		if password == nil {
			return nil, errors.New("private key password is required for encrypted private keys")
		}

		if decrypted, e = x509.DecryptPEMBlock(pemBlock, password); e != nil {
			return
		}
	}
	key, e = parsePKCSPrivateKey(decrypted)
	return
}

// ParsePrivateKey using PKCS1 or PKCS8
func parsePKCSPrivateKey(decryptedKey []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(decryptedKey); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(decryptedKey); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("unsupportesd private key type in PKCS8 wrapping")
		}
	}
	return nil, fmt.Errorf("failed to parse private key")
}

// parseContentLength trims whitespace from cl and returns -1 if can't purse uint, or the value if it's no less than 0
func parseContentLength(cl string) int64 {
	cl = textproto.TrimString(cl)
	n, err := strconv.ParseUint(cl, 10, 63)
	if err != nil {
		return -1
	}
	return int64(n)
}

func generateRandUUID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	uuid := fmt.Sprintf("%x%x%x%x%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	return uuid, nil
}

// IsEnvVarFalse is used for checking if an environment variable is explicitly set to false, otherwise would set it true by default
func IsEnvVarFalse(envVarKey string) bool {
	val, existed := os.LookupEnv(envVarKey)
	return existed && strings.ToLower(val) == "false"
}

// IsEnvVarTrue is used for checking if an environment variable is explicitly set to true, otherwise would set it true by default
func IsEnvVarTrue(envVarKey string) bool {
	val, existed := os.LookupEnv(envVarKey)
	return existed && strings.ToLower(val) == "true"
}
