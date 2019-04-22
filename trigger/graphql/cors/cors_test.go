// Copyright (c) 2015 TIBCO Software Inc.
// All Rights Reserved.
package cors

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	logger "github.com/project-flogo/core/support/log"
	"github.com/stretchr/testify/assert"
)

const (
	testCorsPrefix = "FOO_"
)

var log = logger.RootLogger()

// Test Has Origin Header method
func TestHasOriginHeaderOk(t *testing.T) {
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	// Set Origin
	r.Header.Set(headerOrigin, "http://foo.com")

	hasHeader := HasOriginHeader(r)

	// assert Success
	assert.Equal(t, true, hasHeader, "Request should have Origin header")
}

// Test Has Origin Header method
func TestHasOriginHeaderFalse(t *testing.T) {
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)

	hasHeader := HasOriginHeader(r)

	// assert Success
	assert.Equal(t, false, hasHeader, "Request should not have Origin header")
}

// Test Handle Preflight with no origin header
func TestHandlePreflightErrorNoOrigin(t *testing.T) {
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	w := httptest.NewRecorder()

	c := New(testCorsPrefix, log)
	c.HandlePreflight(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Response should have 200 status code")

	assert.Equal(t, 1, len(w.HeaderMap), "Response should have only 1 header")

	assert.Equal(t, "application/json", w.HeaderMap.Get("Content-Type"), "Response should have only 1 header Content-Type")
}

// Test Handle Preflight with no access control method header
func TestHandlePreflightErrorNoAccesControlMethod(t *testing.T) {
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	// Set Origin
	r.Header.Set(headerOrigin, "http://foo.com")

	w := httptest.NewRecorder()

	c := New(testCorsPrefix, log)
	c.HandlePreflight(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Response should have 200 status code")

	assert.Equal(t, 1, len(w.HeaderMap), "Response should have only 1 header")

	assert.Equal(t, "application/json", w.HeaderMap.Get("Content-Type"), "Response should have only 1 header Content-Type")
}

// Test Handle Preflight with invalid access control method header
func TestHandlePreflightErrorInvalidAccesControlMethod(t *testing.T) {
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	// Set Origin
	r.Header.Set(headerOrigin, "http://foo.com")
	// Set Access Control
	r.Header.Set(headerAccessControlRequestMethod, "foo")

	w := httptest.NewRecorder()

	c := New(testCorsPrefix, log)
	c.HandlePreflight(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Response should have 200 status code")

	assert.Equal(t, 1, len(w.HeaderMap), "Response should have only 1 header")

	assert.Equal(t, "application/json", w.HeaderMap.Get("Content-Type"), "Response should have only 1 header Content-Type")
}

// Test Handle Preflight with no access control header header
func TestHandlePreflightErrorInvalidAccesControlHeader(t *testing.T) {
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	// Set Origin
	r.Header.Set(headerOrigin, "http://foo.com")
	// Set Access Control
	r.Header.Set(headerAccessControlRequestMethod, "GET")
	// Set Access Header
	r.Header.Set(headerAccessControlRequestHeaders, "foo")

	w := httptest.NewRecorder()

	c := New(testCorsPrefix, log)
	c.HandlePreflight(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Response should have 200 status code")

	assert.Equal(t, 1, len(w.HeaderMap), "Response should have only 1 header")

	assert.Equal(t, "application/json", w.HeaderMap.Get("Content-Type"), "Response should have only 1 header Content-Type")
}

// Test Handle Preflight ok
func TestHandlePreflightOkNoAllowCredentialsNorMaxAge(t *testing.T) {
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	// Set Origin
	r.Header.Set(headerOrigin, "http://foo.com")
	// Set Access Control
	r.Header.Set(headerAccessControlRequestMethod, "GET")
	// Set Access Header
	r.Header.Set(headerAccessControlRequestHeaders, "Content-Type , Content-Length")

	w := httptest.NewRecorder()

	c := New(testCorsPrefix, log)
	c.HandlePreflight(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Response should have 200 status code")

	// Response should have Access-Control-Allow-Origin header
	assert.Equal(t, w.HeaderMap.Get(headerAccessControlAllowOrigin), "*", "Response should have star allowOrigin Header")
	// Response should have Access-Control-Allow-Origin header
	assert.Equal(t, corsAllowMethodsDefault, w.HeaderMap.Get(headerAccessControlAllowMethods), "Response should have methods Header")
	// Response should have Access-Control-Allow-Headers
	assert.Equal(t, corsAllowHeadersDefault, w.HeaderMap.Get(headerAccessControlAllowHeaders), "Response should have headers Header")
	// Response should have Access-Control-Expose-Headers
	assert.Equal(t, corsExposeHeadersDefault, w.HeaderMap.Get(headerAccessControlExposeHeaders), "Response should have expose headers Header")
	// Response should not have Access-Control-Allow-Credentials
	assert.Equal(t, "", w.HeaderMap.Get(headerAccessControlAllowCredentials), "Response should not have credentials Header")
	// Response should not have Access-Control-Max-Age
	assert.Equal(t, "", w.HeaderMap.Get(headerAccessControlMaxAge), "Response should not have max age Header")

}

// Test Handle Preflight ok
func TestHandlePreflightOkForLowercase(t *testing.T) {
	// Setup Environment
	previousCredentials := os.Getenv(testCorsPrefix + corsAllowCredentialsKey)
	os.Setenv(testCorsPrefix+corsAllowCredentialsKey, "true")
	defer os.Setenv(testCorsPrefix+corsAllowCredentialsKey, previousCredentials)

	previousMaxAge := os.Getenv(testCorsPrefix + corsMaxAgeKey)
	os.Setenv(testCorsPrefix+corsMaxAgeKey, "20")
	defer os.Setenv(testCorsPrefix+corsMaxAgeKey, previousMaxAge)
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	// Set Origin
	r.Header.Set(headerOrigin, "http://foo.com")
	// Set Access Control
	r.Header.Set(headerAccessControlRequestMethod, "get")
	// Set Access Header
	r.Header.Set(headerAccessControlRequestHeaders, "content-type , content-length")

	w := httptest.NewRecorder()

	c := New(testCorsPrefix, log)
	c.HandlePreflight(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Response should have 200 status code")

	// Response should have Access-Control-Allow-Origin header
	assert.Equal(t, "*", w.HeaderMap.Get(headerAccessControlAllowOrigin), "Response should have star allowOrigin Header")
	// Response should have Access-Control-Allow-Origin header
	assert.Equal(t, corsAllowMethodsDefault, w.HeaderMap.Get(headerAccessControlAllowMethods), "Response should have methods Header")
	// Response should have Access-Control-Allow-Headers
	assert.Equal(t, corsAllowHeadersDefault, w.HeaderMap.Get(headerAccessControlAllowHeaders), "Response should have headers Header")
	// Response should have Access-Control-Expose-Headers
	assert.Equal(t, corsExposeHeadersDefault, w.HeaderMap.Get(headerAccessControlExposeHeaders), "Response should have expose headers Header")
	// Response should not have Access-Control-Allow-Credentials
	assert.Equal(t, "true", w.HeaderMap.Get(headerAccessControlAllowCredentials), "Response should have credentials Header")
	// Response should not have Access-Control-Max-Age
	assert.Equal(t, "20", w.HeaderMap.Get(headerAccessControlMaxAge), "Response should have max age Header")

}

// Test Handle Preflight ok
func TestHandlePreflightOk(t *testing.T) {
	// Setup Environment
	previousCredentials := os.Getenv(testCorsPrefix + corsAllowCredentialsKey)
	os.Setenv(testCorsPrefix+corsAllowCredentialsKey, "true")
	defer os.Setenv(testCorsPrefix+corsAllowCredentialsKey, previousCredentials)

	previousMaxAge := os.Getenv(testCorsPrefix + corsMaxAgeKey)
	os.Setenv(testCorsPrefix+corsMaxAgeKey, "20")
	defer os.Setenv(testCorsPrefix+corsMaxAgeKey, previousMaxAge)
	// Create request
	r, _ := http.NewRequest("GET", "http://foo.com", nil)
	// Set Origin
	r.Header.Set(headerOrigin, "http://foo.com")
	// Set Access Control
	r.Header.Set(headerAccessControlRequestMethod, "GET")
	// Set Access Header
	r.Header.Set(headerAccessControlRequestHeaders, "Content-Type , Content-Length")

	w := httptest.NewRecorder()

	c := New(testCorsPrefix, log)
	c.HandlePreflight(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "Response should have 200 status code")

	// Response should have Access-Control-Allow-Origin header
	assert.Equal(t, "*", w.HeaderMap.Get(headerAccessControlAllowOrigin), "Response should have star allowOrigin Header")
	// Response should have Access-Control-Allow-Origin header
	assert.Equal(t, corsAllowMethodsDefault, w.HeaderMap.Get(headerAccessControlAllowMethods), "Response should have methods Header")
	// Response should have Access-Control-Allow-Headers
	assert.Equal(t, corsAllowHeadersDefault, w.HeaderMap.Get(headerAccessControlAllowHeaders), "Response should have headers Header")
	// Response should have Access-Control-Expose-Headers
	assert.Equal(t, corsExposeHeadersDefault, w.HeaderMap.Get(headerAccessControlExposeHeaders), "Response should have expose headers Header")
	// Response should not have Access-Control-Allow-Credentials
	assert.Equal(t, "true", w.HeaderMap.Get(headerAccessControlAllowCredentials), "Response should have credentials Header")
	// Response should not have Access-Control-Max-Age
	assert.Equal(t, "20", w.HeaderMap.Get(headerAccessControlMaxAge), "Response should have max age Header")

}

func TestIsValidAccessControlMethodOk(t *testing.T) {

	valid := isValidAccessControlMethod("GET", testCorsPrefix, log)
	assert.Equal(t, true, valid, "GET control method should be valid")
}

func TestIsValidAccessControlMethodFail(t *testing.T) {

	valid := isValidAccessControlMethod("foo", testCorsPrefix, log)
	assert.Equal(t, false, valid, "foo control method should be in valid")
}

func TestIsValidAccessControlMethodFailEmptyMethod(t *testing.T) {

	valid := isValidAccessControlMethod("", testCorsPrefix, log)
	assert.Equal(t, false, valid, "empty control method should be in valid")
}

func TestIsValidAccessControlHeadersOk(t *testing.T) {

	valid := isValidAccessControlHeaders("Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, x-requested-with, Accept", testCorsPrefix, log)
	assert.Equal(t, true, valid, "Headers should be valid")
}

func TestIsValidAccessControlHeadersOkJustOneHeader(t *testing.T) {

	valid := isValidAccessControlHeaders("Content-Type", testCorsPrefix, log)
	assert.Equal(t, true, valid, "Headers should be valid")
}

func TestIsValidAccessControlHeadersOkJustTwoHeaders(t *testing.T) {

	valid := isValidAccessControlHeaders("Content-Type , Content-Length", testCorsPrefix, log)
	assert.Equal(t, true, valid, "Headers should be valid")

}

func TestIsValidAccessControlHeadersOkEmptyHeaders(t *testing.T) {

	valid := isValidAccessControlHeaders("", testCorsPrefix, log)
	assert.Equal(t, true, valid, "Headers should be valid")
}

func TestIsValidAccessControlHeadersFailEmptyHeaders(t *testing.T) {

	valid := isValidAccessControlHeaders(" ", testCorsPrefix, log)
	assert.Equal(t, false, valid, "Headers should be invalid")

}

func TestIsValidAccessControlHeadersFailInvalidHeaders(t *testing.T) {

	valid := isValidAccessControlHeaders("foo", testCorsPrefix, log)
	assert.Equal(t, false, valid, "Headers should be invalid")
}
