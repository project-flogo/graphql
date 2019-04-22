package graphql

import (
	"errors"
	"fmt"
)

//Constants
const (
	//CategoryName = "GraphQL"

	//Info Messages
	TriggerInitialize = 1001
	StartingServer    = 1002
	ServerProperties  = 1003
	CORSPreFlight     = 1004

	//Debug Message
	ExecutingMethod        = 2001
	InterfaceUnionResolver = 2002
	QueryType              = 2003
	MutationType           = 2004
	Schema                 = 2005
	ReceivedRequest        = 2006
	FieldResolver          = 2007
	GraphQLRequest         = 2008
	GraphQLResponse        = 2009
	FlowReturnValue        = 2010

	//Error Messages
	DefaultError              = 4001
	ParsingSchemaError        = 4002
	BuildingSchemaError       = 4003
	MissingServerKeyError     = 4004
	GraphqlError              = 4005
	ErrorProcessingRequest    = 4006
	ErrorLoadingCertsFromFile = 4007
)

var messages = make(map[int]string)

func init() {
	// Info
	messages[TriggerInitialize] = "Initializing GraphQL Trigger - [%s]"
	messages[ReceivedRequest] = "Received request for '%s'"
	messages[StartingServer] = "Starting GraphQL Server..."
	messages[ServerProperties] = "Secure:[%t] Port:[%d] Path:[%s]"

	// Debug
	messages[ExecutingMethod] = "Executing method [%s]"
	messages[InterfaceUnionResolver] = "Trying to find concrete type.. Resolver received type with data: %v"
	messages[QueryType] = "QueryType resolved to: %v"
	messages[MutationType] = "MutationType resolved to: %v"
	messages[Schema] = "GraphQL Schema configured as: %v"
	messages[FieldResolver] = "Calling flow with arguments: %v"
	messages[CORSPreFlight] = "Received [OPTIONS] request to CorsPreFlight: %+v"
	messages[GraphQLRequest] = "GraphQL request received: %+v"
	messages[GraphQLResponse] = "GraphQL response: %+v"
	messages[FlowReturnValue] = "Value returned from flow: %+v"

	// Error
	messages[ParsingSchemaError] = "Error while parsing Graphql schema: %s"
	messages[BuildingSchemaError] = "Error building Graphql schema from ast.Document: %s"
	messages[MissingServerKeyError] = "Server Key and CA certificate must be configured for secure connection"
	messages[GraphqlError] = "Error processing GraphQL request: %#v"
	messages[ErrorProcessingRequest] = "Error in http request: %v"
	messages[ErrorLoadingCertsFromFile] = "Error in reading certificates : %v"
}

// TODO: //GetError to create trigger error
// func GetError(errConst int, triggerName string, params ...interface{}) *trigger.Error {
// 	errCode := CategoryName + "-" + triggerName + "-" + string(errConst)
// 	return trigger.NewError(GetMessage(errConst, params...), errCode, nil)
// }

//GetError to create error -- Since Error is not implemented for trigger, error code is not built
func GetError(errConst int, triggerName string, params ...interface{}) error {
	return errors.New(GetMessage(errConst, params...))
}

//GetMessage to get error message
func GetMessage(msgConst int, params ...interface{}) string {
	if params != nil {
		return fmt.Sprintf(messages[msgConst], params...)
	}
	return messages[msgConst]
}
