package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/TIBCOSoftware/flogo-lib/core/data"
	"github.com/TIBCOSoftware/flogo-lib/core/trigger"
	"github.com/TIBCOSoftware/flogo-lib/logger"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/julienschmidt/httprouter"
	"github.com/project-flogo/graphql/trigger/graphql/cors"

	"net/http"
	"net/url"
)

const (
	// CorsPrefix constant
	CorsPrefix = "GRAPHQL_TRIGGER"

	// input values
	ivPort             = "port"
	ivPath             = "path"
	ivGraphqlSchema    = "graphqlSchema"
	ivResolverFor      = "resolverFor"
	ivOperation        = "operation"
	ivSecureConnection = "secureConnection"
	ivServerKey        = "serverKey"
	ivCACertificate    = "caCertificate"

	contentTypeJSON    = "application/json"
	contentTypeGraphQL = "application/graphql"
)

// log is the default package logger
var log = logger.GetLogger("trigger-tibco-graphql")

// global maps and variables
var graphQLSchema *graphql.Schema
var gqlTypMap map[string]graphql.Type
var astIntfMap map[string]*ast.InterfaceDefinition
var astIntfImpl map[string][]*ast.ObjectDefinition
var astUnionMap map[string]*ast.UnionDefinition
var gqlUnionTypes map[string][]*graphql.Object
var astObjFieldDef map[string][]*ast.FieldDefinition

var rootQueryName string
var rootMutationName string
var foundSchemaElement bool

// GraphQLTrigger is a stub for the Trigger implementation
type GraphQLTrigger struct {
	metadata *trigger.Metadata
	server   *Server
	config   *trigger.Config
}

//NewFactory create a new Trigger factory
func NewFactory(md *trigger.Metadata) trigger.Factory {
	return &GraphQLFactory{metadata: md}
}

// GraphQLFactory Trigger factory
type GraphQLFactory struct {
	metadata *trigger.Metadata
}

//New Creates a new trigger instance for a given id
func (t *GraphQLFactory) New(config *trigger.Config) trigger.Trigger {
	return &GraphQLTrigger{metadata: t.metadata, config: config}
}

// Metadata implements trigger.Trigger.Metadata
func (t *GraphQLTrigger) Metadata() *trigger.Metadata {
	return t.metadata
}

// Start implements util.Managed.Start
func (t *GraphQLTrigger) Start() error {
	return t.server.Start()
}

// Stop implements util.Managed.Stop
func (t *GraphQLTrigger) Stop() error {
	return t.server.Stop()
}

// Initialize trigger
func (t *GraphQLTrigger) Initialize(ctx trigger.InitContext) error {
	log.Info(GetMessage(TriggerInitialize, t.config.Name))
	router := httprouter.New()

	if t.config.Settings == nil {
		return GetError(ConfigurationMissing, t.config.Name, t.config.Id, "Settings")
	}

	if _, ok := t.config.Settings[ivPort]; !ok {
		return GetError(ConfigurationMissing, t.config.Name, t.config.Id, "Port")
	}

	if _, ok := t.config.Settings[ivPath]; !ok {
		return GetError(ConfigurationMissing, t.config.Name, t.config.Id, "Path")
	}

	if _, ok := t.config.Settings[ivGraphqlSchema]; !ok {
		return GetError(ConfigurationMissing, t.config.Name, t.config.Id, "GraphqlSchema")
	}
	path := t.config.GetSetting(ivPath)
	addr := ":" + t.config.GetSetting(ivPort)

	schemaMeta := t.config.Settings[ivGraphqlSchema]
	schemaString := schemaMeta.(string)


	// 1. Parse user schema into ast.Document
	astDoc, err := parser.Parse(parser.ParseParams{
		Source: string(schemaString),
		Options: parser.ParseOptions{
			NoLocation: true,
		},
	})

	if err != nil {
		return GetError(ParsingSchemaError, t.config.Name, err.Error())
	}

	// 2. Build Graphql objects from ast.Document
	t.buildGraphqlTypes(astDoc)

	// 3. Build Graphql schema from ast.Document
	graphQLSchema, err = t.buildGraphqlSchema(astDoc, ctx.GetHandlers())

	if err != nil {
		return GetError(BuildingSchemaError, t.config.Name, err.Error())
	}

	// 4. Setup routes for the path & verb
	router.OPTIONS(path, handleCorsPreflight) // for CORS
	router.Handle("GET", path, newActionHandler(t))
	router.Handle("POST", path, newActionHandler(t))

	host := "http://localhost"
	t.server = NewServer(addr, router)
	t.server.secureConnection, _ = data.CoerceToBoolean(t.config.Settings[ivSecureConnection])
	if t.server.secureConnection == true {
		logger.Info(EnableSecureConnection)
		t.server.serverKey, _ = data.CoerceToString(t.config.Settings[ivServerKey])
		t.server.caCertificate, _ = data.CoerceToString(t.config.Settings[ivCACertificate])

		if t.server.serverKey == "" || t.server.caCertificate == "" {
			return GetError(MissingServerKeyError, t.config.Name)
		}

		if strings.HasPrefix(t.server.serverKey,"file://") {
			// Its file
			fileName := t.server.serverKey[7:]
			serverKey, err := ioutil.ReadFile(fileName)
			if err != nil {
				return GetError(ErrorLoadingCertsFromFile, t.config.Name, err.Error())
			}
			t.server.serverKey = string(serverKey)
		}

		if strings.HasPrefix(t.server.caCertificate,"file://") {
			// Its file
			fileName := t.server.caCertificate[7:]
			serverCert, err := ioutil.ReadFile(fileName)
			if err != nil {
				return GetError(ErrorLoadingCertsFromFile, t.config.Name, err.Error())
			}
			t.server.serverKey = string(serverCert)
		}


		host = "https://localhost"
	}
	log.Info(GetMessage(ListeningOnPort, host+addr+path))
	return nil
}

// TODO: Add support for Scalar type
// Builds an object for each type in the graphql schema and stores it in a type map.
func (t *GraphQLTrigger) buildGraphqlTypes(doc *ast.Document) {
	log.Debug(GetMessage(ExecutingMethod, "buildGraphqlTypes"))
	gqlTypMap = make(map[string]graphql.Type)
	astIntfMap = make(map[string]*ast.InterfaceDefinition)
	astUnionMap = make(map[string]*ast.UnionDefinition)

	for _, def := range doc.Definitions {
		switch def.GetKind() {
		case "InterfaceDefinition":
			intfNode := def.(*ast.InterfaceDefinition)
			intf := graphql.NewInterface(
				graphql.InterfaceConfig{
					Name: intfNode.Name.Value,
				})
			gqlTypMap[intf.Name()] = intf
			astIntfMap[intf.Name()] = intfNode
		case "ObjectDefinition":
			objNode := def.(*ast.ObjectDefinition)
			obj := graphql.NewObject(
				graphql.ObjectConfig{
					Name: objNode.Name.Value,
				})
			gqlTypMap[obj.Name()] = obj
		case "UnionDefinition":
			// not creating graphql.NewUnion(), since Types and ResolveType are mandatory fields to provide
			unionNode := def.(*ast.UnionDefinition)
			astUnionMap[unionNode.Name.Value] = unionNode
		case "InputObjectDefinition":
			inputObjNode := def.(*ast.InputObjectDefinition)
			inputObj := graphql.NewInputObject(
				graphql.InputObjectConfig{
					Name: inputObjNode.Name.Value,
				})
			gqlTypMap[inputObj.Name()] = inputObj
		case "EnumDefinition":
			enumNode := def.(*ast.EnumDefinition)
			enumConfigMap := make(graphql.EnumValueConfigMap)
			for _, ev := range enumNode.Values {
				enumConfigMap[ev.Name.Value] = &graphql.EnumValueConfig{
					Value: ev.Name.Value,
				}
			}
			enum := graphql.NewEnum(
				graphql.EnumConfig{
					Name:   enumNode.Name.Value,
					Values: enumConfigMap,
				})
			gqlTypMap[enum.Name()] = enum
		case "SchemaDefinition":
			foundSchemaElement = true
			sNode := def.(*ast.SchemaDefinition)
			for _, od := range sNode.OperationTypes {
				if od.Operation == "query" {
					rootQueryName = od.Type.Name.Value
				} else if od.Operation == "mutation" {
					rootMutationName = od.Type.Name.Value
				}
			}
		}
	}
	fillFieldsAndInterfaces(doc)
}

// Once the base types are parsed - fill in the fields and interfaces for each object and interface type
// This step is separated to allow for fields to have the same parent type.
func fillFieldsAndInterfaces(doc *ast.Document) {
	log.Debug(GetMessage(ExecutingMethod, "fillFieldsAndInterfaces"))
	astObjFieldDef = make(map[string][]*ast.FieldDefinition) // collects list of fields for each Object type
	astIntfImpl = make(map[string][]*ast.ObjectDefinition)   // collects list of implementations(objects) for each interface type
	gqlUnionTypes = make(map[string][]*graphql.Object)       // collects list of objects in a union type

	// do interfaces first
	for _, intfNode := range astIntfMap {
		intf := gqlTypMap[intfNode.Name.Value]
		intf = graphql.NewInterface(
			graphql.InterfaceConfig{
				Name:        intfNode.Name.Value,
				Fields:      getFields(intfNode.Fields),
				ResolveType: interfaceAndUnionResolver(),
				Description: GetAstStringValue(intfNode.Description),
			})
		gqlTypMap[intf.Name()] = intf
	}

	for _, def := range doc.Definitions {
		if def.GetKind() == "ObjectDefinition" {
			objNode := def.(*ast.ObjectDefinition)
			obj := gqlTypMap[objNode.Name.Value].(*graphql.Object)
			obj = graphql.NewObject(
				graphql.ObjectConfig{
					Name:        objNode.Name.Value,
					Fields:      getFields(objNode.Fields),
					Interfaces:  getInterfaces(objNode),
					Description: GetAstStringValue(objNode.Description),
				})
			gqlTypMap[obj.Name()] = obj
			astObjFieldDef[obj.Name()] = objNode.Fields
		} else if def.GetKind() == "InputObjectDefinition" {
			inputObjNode := def.(*ast.InputObjectDefinition)
			inputObj := gqlTypMap[inputObjNode.Name.Value].(*graphql.InputObject)
			inputObj = graphql.NewInputObject(
				graphql.InputObjectConfig{
					Name:        inputObjNode.Name.Value,
					Fields:      getInputFields(inputObjNode.Fields),
					Description: GetAstStringValue(inputObjNode.Description),
				})
			gqlTypMap[inputObj.Name()] = inputObj
		}
	}

	// do unions last
	for _, unionNode := range astUnionMap {
		union := graphql.NewUnion(
			graphql.UnionConfig{
				Name:        unionNode.Name.Value,
				Types:       getUnionTypes(unionNode.Types),
				ResolveType: interfaceAndUnionResolver(),
			})
		gqlTypMap[union.Name()] = union
		gqlUnionTypes[union.Name()] = union.Types()
	}
	fixSelfRefereningTypes(doc)
}

// Re-add all the fields to interfaces and objects to fix self referencing types. This will ensure all types contain parents fields.
func fixSelfRefereningTypes(doc *ast.Document) {
	log.Debug(GetMessage(ExecutingMethod, "fixSelfRefereningTypes"))
	for _, def := range doc.Definitions {
		if def.GetKind() == "InterfaceDefinition" {
			intfNode := def.(*ast.InterfaceDefinition)
			intf := gqlTypMap[intfNode.Name.Value].(*graphql.Interface)
			for _, fd := range intfNode.Fields {
				intf.AddFieldConfig(fd.Name.Value, &graphql.Field{
					Name:        fd.Name.Value,
					Type:        CoerceType(fd.Type),
					Description: GetAstStringValue(fd.Description),
				})
			}
		} else if def.GetKind() == "ObjectDefinition" {
			objNode := def.(*ast.ObjectDefinition)
			obj := gqlTypMap[objNode.Name.Value].(*graphql.Object)
			for _, fd := range objNode.Fields {
				obj.AddFieldConfig(fd.Name.Value, &graphql.Field{
					Name:        fd.Name.Value,
					Type:        CoerceType(fd.Type),
					Description: GetAstStringValue(fd.Description),
				})
			}
		}
	}
}

// Builds graphql.Fields from []ast.FieldDefinition
func getFields(astFields []*ast.FieldDefinition) graphql.Fields {
	fields := make(graphql.Fields)
	for _, fd := range astFields {
		fields[fd.Name.Value] = &graphql.Field{
			Name:        fd.Name.Value,
			Type:        CoerceType(fd.Type),
			Description: GetAstStringValue(fd.Description),
		}
	}
	return fields
}

// Builds graphql.InputObjectFieldConfigMap from []ast.InputValueDefinition
func getInputFields(astFields []*ast.InputValueDefinition) graphql.InputObjectConfigFieldMap {
	fields := make(graphql.InputObjectConfigFieldMap)
	for _, ivd := range astFields {
		fields[ivd.Name.Value] = &graphql.InputObjectFieldConfig{
			Type:         CoerceType(ivd.Type),
			DefaultValue: GetValue(ivd.DefaultValue),
			Description:  GetAstStringValue(ivd.Description),
		}
	}
	return fields
}

// Returns graphql.Interfaces for a given ast.ObjectDefinition
func getInterfaces(objNode *ast.ObjectDefinition) []*graphql.Interface {
	astIntfs := objNode.Interfaces
	intfs := []*graphql.Interface{}
	for _, ai := range astIntfs {
		if gqlTypMap[ai.Name.Value] != nil {
			astIntfImpl[ai.Name.Value] = append(astIntfImpl[ai.Name.Value], objNode)
			intfs = append(intfs, gqlTypMap[ai.Name.Value].(*graphql.Interface))
		}
	}
	return intfs
}

// Returns list of Object types for a given union type
func getUnionTypes(astUnionTypes []*ast.Named) []*graphql.Object {
	unionTypes := []*graphql.Object{}
	for _, ut := range astUnionTypes {
		if _, ok := gqlTypMap[ut.Name.Value]; ok {
			unionTypes = append(unionTypes, gqlTypMap[ut.Name.Value].(*graphql.Object))
		}
	}
	return unionTypes
}

// Interface and Union resolver to determine what concrete type the value passed from flow is.
func interfaceAndUnionResolver() graphql.ResolveTypeFn {
	return func(p graphql.ResolveTypeParams) *graphql.Object {
		log.Debug(GetMessage(InterfaceUnionResolver, p.Value))
		possibleType := getPossibleType(p)
		if possibleType == "" {
			log.Error("Error finding concrete type for interface resolver")
			return nil
		}
		return gqlTypMap[possibleType].(*graphql.Object)
	}
}

// TODO: Need to find better way to determine concrete type
// Compares the fields of data with all implementations(objects) of the interface and returns the first matching value
func getPossibleType(p graphql.ResolveTypeParams) string {
	outputType := GetInterfaceOrUnionType(p.Info.ReturnType)
	objNodes := []*graphql.Object{}
	if _, ok := astIntfImpl[outputType.Name()]; ok {
		// output type is a interface -- get list of *graphql.Object from ast.ObjectDefinition
		objDefNodes := astIntfImpl[outputType.Name()]
		for _, odn := range objDefNodes {
			if on, ok := gqlTypMap[odn.Name.Value]; ok {
				objNodes = append(objNodes, on.(*graphql.Object))
			}
		}
	} else {
		// output type is a union -- get list of *graphql.Object
		objNodes = gqlUnionTypes[outputType.Name()]
	}

	// get data
	var data map[string]interface{}
	switch p.Value.(type) {
	case map[string]interface{}:
		data = p.Value.(map[string]interface{})
	case string:
		err := json.Unmarshal([]byte(p.Value.(string)), &data)
		if err != nil {
			log.Error("Error parsing data in interface resolver")
			return ""
		}
	}

	// compare each field of data with object fields
	for _, obj := range objNodes {
		objFields := obj.Fields()
		containsAllFields := true
		for k := range data {
			if _, ok := objFields[k]; !ok {
				containsAllFields = false
				break
			}
		}
		if containsAllFields {
			return obj.Name()
		}
	}
	return ""
}

// Builds graphql schema by aggregating query and mutation type.
func (t *GraphQLTrigger) buildGraphqlSchema(doc *ast.Document, handlers []*trigger.Handler) (*graphql.Schema, error) {
	log.Debug(GetMessage(ExecutingMethod, "buildGraphqlSchema"))
	// if "schema" element does not exist, use default names for query and mutation
	if !foundSchemaElement {
		rootQueryName = "Query"
		rootMutationName = "Mutation"
	}

	queryType := t.buildArgsAndResolvers(rootQueryName, "Query", handlers)
	log.Debug(GetMessage(QueryType, queryType))
	mutationType := t.buildArgsAndResolvers(rootMutationName, "Mutation", handlers)
	log.Debug(GetMessage(MutationType, mutationType))

	typesArr := []graphql.Type{}
	for key, typ := range gqlTypMap {
		if key != rootQueryName && key != rootMutationName {
			typesArr = append(typesArr, typ)
		}
	}

	schema, err := graphql.NewSchema(
		graphql.SchemaConfig{
			Types:    typesArr,
			Query:    queryType,
			Mutation: mutationType,
		})
	if err != nil {
		return nil, err
	}
	log.Debug(GetMessage(Schema, schema))
	return &schema, nil
}

// Builds Arguments and Resolvers for query and mutation fields
func (t *GraphQLTrigger) buildArgsAndResolvers(targetOperationName string, operationType string, handlers []*trigger.Handler) *graphql.Object {
	if fieldDefArr, ok := astObjFieldDef[targetOperationName]; ok {
		gqlFields := make(graphql.Fields)
		for _, fd := range fieldDefArr {
			args := make(graphql.FieldConfigArgument) // array of args
			for _, a := range fd.Arguments {
				args[a.Name.Value] = &graphql.ArgumentConfig{
					DefaultValue: GetValue(a.DefaultValue),
					Description:  GetAstStringValue(a.Description),
					Type:         CoerceType(a.Type),
				}
			}
			for _, handler := range handlers {
				if strings.EqualFold(handler.GetStringSetting(ivResolverFor), fd.Name.Value) &&
					strings.EqualFold(handler.GetStringSetting(ivOperation), operationType) {
					gqlFields[fd.Name.Value] = &graphql.Field{
						Args:        args,
						Name:        fd.Name.Value,
						Description: GetAstStringValue(fd.Description),
						Type:        CoerceType(fd.Type),
						Resolve:     fieldResolver(handler), // The flow to call when the query/mutation field is requested
					}
				}
			}
		}
		gqlObject := graphql.NewObject(
			graphql.ObjectConfig{
				Name:   targetOperationName,
				Fields: gqlFields,
			})
		return gqlObject
	}
	return nil
}

// Executes the flow in the application. Triggered by query/mutation field
func fieldResolver(handler *trigger.Handler) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		log.Debug(GetMessage(FieldResolver, p.Args))

		triggerData := map[string]interface{}{
			"arguments": p.Args,
		}

		// execute flow
		flowReturnValue, err := handler.Handle(context.Background(), triggerData)
		if err != nil {
			return nil, err
		}

		var replyData interface{}
		dataAttr, ok := flowReturnValue["data"]
		if ok && dataAttr != nil {
			attrValue := dataAttr.Value()
			if attrValue != nil {
				if complexV, ok := attrValue.(*data.ComplexObject); ok {
					replyData = complexV.Value
				} else {
					replyData = attrValue
				}
			}
		}

		replyDataObj, err := data.CoerceToObject(replyData)
		if err != nil {
			return nil, err
		}
		// returning first object's value in map
		for _, v := range replyDataObj {
			return v, nil
		}
		return nil, nil
	}
}

// Handles the cors preflight request
func handleCorsPreflight(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Info(GetMessage(CORSPreFlight, r))
	c := cors.New(CorsPrefix, log)
	c.HandlePreflight(w, r)
}

// RequestOptions struct for graphql request
type RequestOptions struct {
	Query         string                 `json:"query" url:"query" schema:"query"`
	Variables     map[string]interface{} `json:"variables" url:"variables" schema:"variables"`
	OperationName string                 `json:"operationName" url:"operationName" schema:"operationName"`
}

// Builds RequestOptions from url values
func getFromForm(values url.Values) *RequestOptions {
	query := values.Get("query")
	if query != "" {
		// get variables map
		variables := make(map[string]interface{}, len(values))
		variablesStr := values.Get("variables")
		json.Unmarshal([]byte(variablesStr), &variables)

		return &RequestOptions{
			Query:         query,
			Variables:     variables,
			OperationName: values.Get("operationName"),
		}
	}
	return nil
}

// Builds RequestOptions for different content types
func getRequestOptions(r *http.Request) (*RequestOptions, error) {
	if reqOpt := getFromForm(r.URL.Query()); reqOpt != nil {
		return reqOpt, nil
	}

	if r.Method == http.MethodGet {
		err := fmt.Errorf("%v", "No query parameter found in request url. Please provide query parameter as part of GET request.")
		return nil, err
	}

	if r.Body == nil {
		err := fmt.Errorf("%v", "Empty body in POST request. Please provide query parameter in request or content in body.")
		return nil, err
	}

	contentType := r.Header.Get("Content-Type")

	// Supported content-types are application/json and application/graphql
	switch contentType {
	case contentTypeGraphQL:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return &RequestOptions{
			Query: string(body),
		}, nil
	case contentTypeJSON:
		var opts RequestOptions
		err := json.NewDecoder(r.Body).Decode(&opts)
		if err != nil {
			return nil, err
		}
		return &opts, nil
	default:
		err := fmt.Errorf("%v", "Invalid content type. Supported content types for POST method are application/json and application/graphql.")
		return nil, err
	}
}

// Handles incoming http request from client
func newActionHandler(rt *GraphQLTrigger) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		log.Debugf(GetMessage(ReceivedRequest, rt.config.Name))
		c := cors.New(CorsPrefix, log)
		c.WriteCorsActualRequestHeaders(w)

		// get request options
		reqOpts, err := getRequestOptions(r)

		if err != nil {
			log.Error(GetMessage(ErrorProcessingRequest, err.Error()))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Process the request
		result := graphql.Do(graphql.Params{
			OperationName:  reqOpts.OperationName,
			RequestString:  reqOpts.Query,
			Schema:         *graphQLSchema,
			VariableValues: reqOpts.Variables,
		})

		if result != nil {
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			if len(result.Errors) > 0 {
				log.Error(GetMessage(GraphqlError, result.Errors))
				w.WriteHeader(http.StatusBadRequest)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			if err := json.NewEncoder(w).Encode(result); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error(err)
			}
		}
	}
}
