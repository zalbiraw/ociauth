// Copyright (c) 2016, 2018, 2025, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

package internal

import (
	"fmt"
	"os"
	"strings"
)

// Region type for regions
type Region string

const (
	// Default Realm Environment Variable
	defaultRealmEnvVarName = "OCI_DEFAULT_REALM"
)

// defaultRealmForUnknownDeveloperToolConfigurationRegion is the default realm for unknown Developer Tool Configuration Regions
const defaultRealmForUnknownDeveloperToolConfigurationRegion = "oraclecloud.com"

// var ociDeveloperToolConfigurationRegionSchemaList []map[string]string

// Endpoint returns a endpoint for a service
func (region Region) Endpoint(service string) string {
	// Endpoint for dotted region
	if strings.Contains(string(region), ".") {
		return fmt.Sprintf("%s.%s", service, region)
	}
	return fmt.Sprintf("%s.%s.%s", service, region, region.SecondLevelDomain())
}

func (region Region) SecondLevelDomain() string {
	if realmID, ok := regionRealm[region]; ok {
		if secondLevelDomain, ok := realm[realmID]; ok {
			return secondLevelDomain
		}
	}
	if value, ok := os.LookupEnv(defaultRealmEnvVarName); ok {
		return value
	}
	// Debugf("cannot find realm for region : %s, return default realm value.", region)
	if _, ok := realm["oc1"]; !ok {
		return defaultRealmForUnknownDeveloperToolConfigurationRegion
	}
	return realm["oc1"]
}
