// Copyright (c) 2016, 2018, 2025, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	//UsingExpectHeaderEnvVar is the key to determine whether expect 100-continue is enabled or not
	UsingExpectHeaderEnvVar = "OCI_GOSDK_USING_EXPECT_HEADER"
)

// PolymorphicJSONUnmarshaler is the interface to unmarshal polymorphic json payloads
type PolymorphicJSONUnmarshaler interface {
	UnmarshalPolymorphicJSON(data []byte) (interface{}, error)
}

// Makes sure the incoming structure is able to be unmarshaled
// to a request
func checkForValidResponseStruct(s interface{}) (*reflect.Value, error) {
	val := reflect.ValueOf(s)
	for val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil, fmt.Errorf("can not unmarshal to response a pointer to nil structure")
		}
		val = val.Elem()
	}

	if s == nil {
		return nil, fmt.Errorf("can not unmarshal to response a nil structure")
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("can not unmarshal to response, expects struct input. Got %v", val.Kind())
	}

	return &val, nil
}

func intSizeFromKind(kind reflect.Kind) int {
	switch kind {
	case reflect.Int8, reflect.Uint8:
		return 8
	case reflect.Int16, reflect.Uint16:
		return 16
	case reflect.Int32, reflect.Uint32:
		return 32
	case reflect.Int64, reflect.Uint64:
		return 64
	case reflect.Int, reflect.Uint:
		return strconv.IntSize
	default:
		return strconv.IntSize
	}
}

func analyzeValue(stringValue string, kind reflect.Kind, field reflect.StructField) (val reflect.Value, valPointer reflect.Value, err error) {
	switch kind {
	case timeType.Kind():
		var t time.Time
		t, err = tryParsingTimeWithValidFormatsForHeaders([]byte(stringValue), field.Name)
		if err != nil {
			return
		}
		sdkTime := sdkTimeFromTime(t)
		val = reflect.ValueOf(sdkTime)
		valPointer = reflect.ValueOf(&sdkTime)
		return
	case sdkDateType.Kind():
		var t time.Time
		t, err = tryParsingTimeWithValidFormatsForHeaders([]byte(stringValue), field.Name)
		if err != nil {
			return
		}
		sdkDate := sdkDateFromTime(t)
		val = reflect.ValueOf(sdkDate)
		valPointer = reflect.ValueOf(&sdkDate)
		return
	case reflect.Bool:
		var bVal bool
		if bVal, err = strconv.ParseBool(stringValue); err != nil {
			return
		}
		val = reflect.ValueOf(bVal)
		valPointer = reflect.ValueOf(&bVal)
		return
	case reflect.Int:
		size := intSizeFromKind(kind)
		var iVal int64
		if iVal, err = strconv.ParseInt(stringValue, 10, size); err != nil {
			return
		}
		var iiVal int
		iiVal = int(iVal)
		val = reflect.ValueOf(iiVal)
		valPointer = reflect.ValueOf(&iiVal)
		return
	case reflect.Int64:
		size := intSizeFromKind(kind)
		var iVal int64
		if iVal, err = strconv.ParseInt(stringValue, 10, size); err != nil {
			return
		}
		val = reflect.ValueOf(iVal)
		valPointer = reflect.ValueOf(&iVal)
		return
	case reflect.Uint:
		size := intSizeFromKind(kind)
		var iVal uint64
		if iVal, err = strconv.ParseUint(stringValue, 10, size); err != nil {
			return
		}
		var uiVal uint
		uiVal = uint(iVal)
		val = reflect.ValueOf(uiVal)
		valPointer = reflect.ValueOf(&uiVal)
		return
	case reflect.String:
		val = reflect.ValueOf(stringValue)
		valPointer = reflect.ValueOf(&stringValue)
	case reflect.Float32:
		var fVal float64
		if fVal, err = strconv.ParseFloat(stringValue, 32); err != nil {
			return
		}
		var ffVal float32
		ffVal = float32(fVal)
		val = reflect.ValueOf(ffVal)
		valPointer = reflect.ValueOf(&ffVal)
		return
	case reflect.Float64:
		var fVal float64
		if fVal, err = strconv.ParseFloat(stringValue, 64); err != nil {
			return
		}
		val = reflect.ValueOf(fVal)
		valPointer = reflect.ValueOf(&fVal)
		return
	default:
		err = fmt.Errorf("value for kind: %s not supported", kind)
	}
	return
}

// Sets the field of a struct, with the appropriate value of the string
// Only sets basic types
func fromStringValue(newValue string, val *reflect.Value, field reflect.StructField) (err error) {
	if !val.CanSet() {
		err = fmt.Errorf("can not set field name: %s of type: %v", field.Name, val.Type().String())
		return
	}

	kind := val.Kind()
	isPointer := false
	if val.Kind() == reflect.Ptr {
		isPointer = true
		kind = field.Type.Elem().Kind()
	}

	value, valPtr, err := analyzeValue(newValue, kind, field)
	valueType := val.Type()
	if err != nil {
		return
	}
	if !isPointer {
		val.Set(value.Convert(valueType))
	} else {
		val.Set(valPtr)
	}
	return
}

func valueFromPolymorphicJSON(content []byte, unmarshaler PolymorphicJSONUnmarshaler) (val interface{}, err error) {
	err = json.Unmarshal(content, unmarshaler)
	if err != nil {
		return
	}
	val, err = unmarshaler.UnmarshalPolymorphicJSON(content)
	return
}

func valueFromJSONBody(response *http.Response, value *reflect.Value, unmarshaler PolymorphicJSONUnmarshaler) (val interface{}, err error) {
	var content []byte
	content, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}

	if unmarshaler != nil {
		val, err = valueFromPolymorphicJSON(content, unmarshaler)
		return
	}

	val = reflect.New(value.Type()).Interface()
	err = json.Unmarshal(content, &val)
	return
}

func addFromBody(response *http.Response, value *reflect.Value, field reflect.StructField, unmarshaler PolymorphicJSONUnmarshaler) (err error) {
	if response.Body == nil {
		return nil
	}

	tag := field.Tag
	encoding := tag.Get("encoding")
	var iVal interface{}
	switch encoding {
	case "binary":
		value.Set(reflect.ValueOf(response.Body))
		return
	case "plain-text":
		byteArr, e := ioutil.ReadAll(response.Body)
		if e != nil {
			return e
		}
		str := string(byteArr)
		value.Set(reflect.ValueOf(&str))
		return
	default: // If the encoding is not set, we'll decode with json
		iVal, err = valueFromJSONBody(response, value, unmarshaler)
		if err != nil {
			return
		}

		newVal := reflect.ValueOf(iVal)
		if newVal.Kind() == reflect.Ptr {
			newVal = newVal.Elem()
		}
		value.Set(newVal)
		return
	}
}

func addFromHeader(response *http.Response, value *reflect.Value, field reflect.StructField) (err error) {
	var headerName string
	if headerName = field.Tag.Get("name"); headerName == "" {
		return fmt.Errorf("unmarshaling response to a header requires the 'name' tag for field: %s", field.Name)
	}

	headerValue := response.Header.Get(headerName)
	if headerValue == "" {
		return nil
	}

	if err = fromStringValue(headerValue, value, field); err != nil {
		return fmt.Errorf("unmarshaling response to a header failed for field %s, due to %s", field.Name,
			err.Error())
	}
	return
}

func addFromHeaderCollection(response *http.Response, value *reflect.Value, field reflect.StructField) error {
	var headerPrefix string
	if headerPrefix = field.Tag.Get("prefix"); headerPrefix == "" {
		return fmt.Errorf("unmarshaling response to a header-collection requires the 'prefix' tag for field: %s", field.Name)
	}

	mapCollection := make(map[string]string)
	for name, value := range response.Header {
		nameLowerCase := strings.ToLower(name)
		if strings.HasPrefix(nameLowerCase, headerPrefix) {
			headerNoPrefix := strings.TrimPrefix(nameLowerCase, headerPrefix)
			mapCollection[headerNoPrefix] = value[0]
		}
	}

	value.Set(reflect.ValueOf(mapCollection))
	return nil
}

// Populates a struct from parts of a request by reading tags of the struct
func responseToStruct(response *http.Response, val *reflect.Value, unmarshaler PolymorphicJSONUnmarshaler) (err error) {
	if val == nil || !val.IsValid() {
		return fmt.Errorf("invalid reflect.Value passed to responseToStruct")
	}
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		if err != nil {
			return
		}

		sf := typ.Field(i)

		//unexported
		if sf.PkgPath != "" {
			continue
		}

		sv := val.Field(i)
		tag := sf.Tag.Get("presentIn")
		switch tag {
		case "header":
			err = addFromHeader(response, &sv, sf)
		case "header-collection":
			err = addFromHeaderCollection(response, &sv, sf)
		case "body":
			err = addFromBody(response, &sv, sf, unmarshaler)
		case "":
			// Skip fields without presentIn tag
		default:
			err = fmt.Errorf("can not unmarshal field: %s. It needs to contain valid presentIn tag", sf.Name)
		}
	}
	return
}

// UnmarshalResponse hydrates the fields of a struct with the values of a http response, guided
// by the field tags. The directive tag is "presentIn" and it can be either
//   - "header": Will look for the header tagged as "name" in the headers of the struct and set it value to that
//   - "body": It will try to marshal the body from a json string to a struct tagged with 'presentIn: "body"'.
//
// Further this method will consume the body it should be safe to close it after this function
// Notice the current implementation only supports native types:int, strings, floats, bool as the field types
func UnmarshalResponse(httpResponse *http.Response, responseStruct interface{}) (err error) {
	// Check for text/event-stream content type, and return without unmarshalling
	if httpResponse != nil && httpResponse.Header != nil && strings.ToLower(httpResponse.Header.Get("content-type")) == "text/event-stream" {
		return
	}

	var val *reflect.Value
	if val, err = checkForValidResponseStruct(responseStruct); err != nil {
		return
	}

	if err = responseToStruct(httpResponse, val, nil); err != nil {
		return
	}

	return nil
}

// Helper function to judge if this struct is a nopCloser or nopCloserWriterTo
func isNopCloser(readCloser io.ReadCloser) bool {
	if reflect.TypeOf(readCloser) == reflect.TypeOf(io.NopCloser(nil)) || reflect.TypeOf(readCloser) == reflect.TypeOf(io.NopCloser(struct {
		io.Reader
		io.WriterTo
	}{})) {
		return true
	}
	return false
}
