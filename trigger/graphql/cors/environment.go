// Copyright (c) 2015 TIBCO Software Inc.
// All Rights Reserved.

package cors

import (
	"os"
)

// List of constants default values that can be overriden by environment variables
const (
	corsAllowOriginKey          string = "CORS_ALLOW_ORIGIN"
	corsAllowOriginDefault      string = "*"
	corsAllowMethodsKey         string = "CORS_ALLOW_METHODS"
	corsAllowMethodsDefault     string = "POST, GET, OPTIONS, PUT, DELETE, PATCH"
	corsAllowHeadersKey         string = "CORS_ALLOW_HEADERS"
	corsExposeHeadersKey        string = "CORS_EXPOSE_HEADERS"
	corsAllowHeadersDefault     string = "*"
	corsExposeHeadersDefault    string = ""
	corsAllowCredentialsKey     string = "CORS_ALLOW_CREDENTIALS"
	corsAllowCredentialsDefault string = "false"
	corsMaxAgeKey               string = "CORS_MAX_AGE"
	corsMaxAgeDefault           string = ""
)

//GetCorsAllowOrigin get the value for CORS 'AllowOrigin' param from environment variable and the default BS_CORS_ALLOW_ORIGIN_DEFAULT will be used if not found
func GetCorsAllowOrigin(prefix string) string {
	envalue := os.Getenv(prefix + corsAllowOriginKey)
	if envalue == "" {
		return corsAllowOriginDefault
	}
	return envalue
}

//GetCorsAllowMethods get the allowed method for CORS from environment variable and the default BS_CORS_ALLOW_METHODS_DEFAULT will be used if not found
func GetCorsAllowMethods(prefix string) string {
	envalue := os.Getenv(prefix + corsAllowMethodsKey)
	if envalue == "" {
		return corsAllowMethodsDefault
	}
	return envalue
}

//GetCorsAllowHeaders get the value for CORS 'AllowHeaders' param from environment variable and the default BS_CORS_ALLOW_HEADERS_DEFAULT will be used if not found
func GetCorsAllowHeaders(prefix string) string {
	envalue := os.Getenv(prefix + corsAllowHeadersKey)
	if envalue == "" {
		return corsAllowHeadersDefault
	}
	return envalue
}

//GetCorsExposeHeaders get the value for CORS 'ExposeHeaders' param from environment variable and the default BS_CORS_EXPOSE_HEADERS_DEFAULT will be used if not found
func GetCorsExposeHeaders(prefix string) string {
	envalue := os.Getenv(prefix + corsExposeHeadersKey)
	if envalue == "" {
		return corsExposeHeadersDefault
	}
	return envalue
}

//GetCorsAllowCredentials get the value for CORS 'AllowCredentials' param from environment variable and the default BS_CORS_ALLOW_CREDENTIALS_DEFAULT will be used if not found
func GetCorsAllowCredentials(prefix string) string {
	envalue := os.Getenv(prefix + corsAllowCredentialsKey)
	if envalue == "" {
		return corsAllowCredentialsDefault
	}
	return envalue
}

//GetCorsMaxAge get the value for CORS 'Max Age' param from environment variable and the default BS_CORS_ALLOW_CREDENTIALS_DEFAULT will be used if not found
func GetCorsMaxAge(prefix string) string {
	envalue := os.Getenv(prefix + corsMaxAgeKey)
	if envalue == "" {
		return corsMaxAgeDefault
	}
	return envalue
}
