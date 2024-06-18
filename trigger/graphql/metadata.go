package graphql

import (
	"github.com/project-flogo/core/data/coerce"
)

// Settings for trigger
type Settings struct {
	Port             int    `md:"port,required"`             // The port to listen on for requests
	Path             string `md:"path,required"`             // The HTTP resource path
	SecureConnection bool   `md:"secureConnection,required"` // Set to "true" for a secure connection
	ServerKey        string `md:"serverKey"`                 // A PEM encoded private key file
	CACertificate    string `md:"caCertificate"`             // A PEM encoded CA or Server certificate file
	GraphQLSchema    string `md:"graphqlSchema,required"`    // The GraphQL schema for the trigger
	Introspection    bool   `md:"introspection"`             // Introspection toggle for the trigger
}

// HandlerSettings for trigger
type HandlerSettings struct {
	Operation   string `md:"operation,required,allowed(Query,Mutation)"` // GraphQL Operation to be performed
	ResolverFor string `md:"resolverFor,required"`                       // Field name from selected operation
}

// Output of the trigger -- Input into the flow
type Output struct {
	Arguments map[string]interface{} `md:"arguments"` // The input arguments to the field of the operation
	Headers   map[string]string      `md:"headers"`   // The headers from the request
	Fields    map[string]interface{} `md:"fields"`    // The fields from the query or mutation
}

// Reply from the trigger
type Reply struct {
	Data  map[string]interface{} `md:"data"`  // The data to reply with
	Error string                 `md:"error"` // The error to reply with
}

// ToMap to the trigger Output
func (o *Output) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"arguments": o.Arguments,
		"headers":   o.Headers,
		"fields":    o.Fields,
	}
}

// FromMap from the trigger Output
func (o *Output) FromMap(values map[string]interface{}) error {
	var err error
	o.Arguments, err = coerce.ToObject(values["arguments"])
	if err != nil {
		return err
	}
	o.Headers, err = coerce.ToParams(values["headers"])
	if err != nil {
		return err
	}
	o.Fields, err = coerce.ToObject(values["fields"])
	if err != nil {
		return err
	}
	return nil
}

// ToMap to the trigger Reply
func (r *Reply) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"data":  r.Data,
		"error": r.Error,
	}
}

// FromMap from the trigger Reply
func (r *Reply) FromMap(values map[string]interface{}) error {
	var err error
	r.Data, err = coerce.ToObject(values["data"])
	if err != nil {
		return err
	}
	r.Error, err = coerce.ToString(values["error"])
	if err != nil {
		return err
	}
	return nil
}
