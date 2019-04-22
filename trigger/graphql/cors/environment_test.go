// Copyright (c) 2015 TIBCO Software Inc.
// All Rights Reserved.
package cors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test GetCorsAllowOrigin method
func TestGetCorsAllowOriginOk(t *testing.T) {
	allowOrigin := GetCorsAllowOrigin(testCorsPrefix)

	// assert Success
	assert.Equal(t, corsAllowOriginDefault, allowOrigin, "Allow Origin should be default value")
}

// Test GetCorsAllowOrigin method
func TestGetCorsAllowOriginOkModified(t *testing.T) {
	previous := os.Getenv(testCorsPrefix + corsAllowOriginKey)
	defer os.Setenv(testCorsPrefix+corsAllowOriginKey, previous)

	newValue := "fooAllowedOrigin"

	// Change value
	os.Setenv(testCorsPrefix+corsAllowOriginKey, newValue)

	allowOrigin := GetCorsAllowOrigin(testCorsPrefix)

	// assert Success
	assert.Equal(t, newValue, allowOrigin, "Allow Origin should be "+newValue)

}

// Test GetCorsAllowMethods method
func TestGetCorsAllowMethodsOk(t *testing.T) {
	envValue := GetCorsAllowMethods(testCorsPrefix)

	// assert Success
	assert.Equal(t, corsAllowMethodsDefault, envValue, "Allow Method should be default value")
}

// Test GetCorsAllowOrigin method
func TestGetCorsAllowMethodsOkModified(t *testing.T) {
	previous := os.Getenv(testCorsPrefix + corsAllowMethodsKey)
	defer os.Setenv(testCorsPrefix+corsAllowMethodsKey, previous)

	newValue := "fooAllowedMethods"

	// Change value
	os.Setenv(testCorsPrefix+corsAllowMethodsKey, newValue)

	envValue := GetCorsAllowMethods(testCorsPrefix)

	// assert Success
	assert.Equal(t, newValue, envValue, "Allow Methods should be "+newValue)
}

// Test GetCorsAllowHeaders method
func TestGetCorsAllowHeadersOk(t *testing.T) {
	envValue := GetCorsAllowHeaders(testCorsPrefix)

	// assert Success
	assert.Equal(t, corsAllowHeadersDefault, envValue, "Allow Headers should be default value")
}

// Test GetCorsAllowHeaders method
func TestGetCorsAllowHeadersOkModified(t *testing.T) {
	previous := os.Getenv(testCorsPrefix + corsAllowHeadersKey)
	defer os.Setenv(testCorsPrefix+corsAllowHeadersKey, previous)

	newValue := "fooAllowedHeaders"

	// Change value
	os.Setenv(testCorsPrefix+corsAllowHeadersKey, newValue)

	envValue := GetCorsAllowHeaders(testCorsPrefix)

	// assert Success
	assert.Equal(t, newValue, envValue, "Allow Headers should be "+newValue)
}

// Test GetCorsAllowCredentials method
func TestGetCorsAllowCredentialsOk(t *testing.T) {
	envValue := GetCorsAllowCredentials(testCorsPrefix)

	// assert Success
	assert.Equal(t, corsAllowCredentialsDefault, envValue, "Allow Credentials should be default value")
}

// Test GetCorsAllowCredentials method
func TestGetCorsAllowCredentialsOkModified(t *testing.T) {
	previous := os.Getenv(testCorsPrefix + corsAllowCredentialsKey)
	defer os.Setenv(testCorsPrefix+corsAllowCredentialsKey, previous)

	newValue := "true"

	// Change value
	os.Setenv(testCorsPrefix+corsAllowCredentialsKey, newValue)

	envValue := GetCorsAllowCredentials(testCorsPrefix)

	// assert Success
	assert.Equal(t, newValue, envValue, "Allow Credentials should be "+newValue)
}

// Test GetCorsMaxAge method
func TestGetCorsMaxAgeOk(t *testing.T) {
	envValue := GetCorsMaxAge(testCorsPrefix)

	// assert Success
	assert.Equal(t, corsMaxAgeDefault, envValue, "Max Age should be default value")
}

// Test GetCorsAllowCredentials method
func TestGetCorsMaxAgeOkModified(t *testing.T) {
	previous := os.Getenv(testCorsPrefix + corsMaxAgeKey)
	defer os.Setenv(testCorsPrefix+corsMaxAgeKey, previous)

	newValue := "21"

	// Change value
	os.Setenv(testCorsPrefix+corsMaxAgeKey, newValue)

	envValue := GetCorsMaxAge(testCorsPrefix)

	// assert Success
	assert.Equal(t, newValue, envValue, "Max Age should be "+newValue)
}
