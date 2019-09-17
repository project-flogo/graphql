package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/julienschmidt/httprouter"
	"github.com/project-flogo/core/data/coerce"
	"github.com/project-flogo/core/data/metadata"
	logger "github.com/project-flogo/core/support/log"
	"github.com/project-flogo/core/trigger"
	"github.com/project-flogo/graphql/trigger/graphql/cors"

	"net/http"
	"net/url"
)

const (
	corsPrefix = "GRAPHQL_TRIGGER"

	contentTypeJSON    = "application/json"
	contentTypeGraphQL = "application/graphql"
)

// log is the default package logger
var log logger.Logger

var triggerMd = trigger.NewMetadata(&Settings{}, &HandlerSettings{}, &Output{}, &Reply{})

// Trigger is a stub for the GraphQLTrigger implementation
type Trigger struct {
	server             *Server
	settings           *Settings
	id                 string
	graphQLSchema      *graphql.Schema
	gqlTypMap          map[string]graphql.Type
	astIntfMap         map[string]*ast.InterfaceDefinition
	astIntfImpl        map[string][]*ast.ObjectDefinition
	astUnionMap        map[string]*ast.UnionDefinition
	gqlUnionTypes      map[string][]*graphql.Object
	astObjFieldDef     map[string][]*ast.FieldDefinition
	rootQueryName      string
	rootMutationName   string
	foundSchemaElement bool
}

// Factory for trigger
type Factory struct {
}

func init() {
	_ = trigger.Register(&Trigger{}, &Factory{})
}

//New implements trigger.Factory.New
func (*Factory) New(config *trigger.Config) (trigger.Trigger, error) {
	s := &Settings{}
	err := metadata.MapToStruct(config.Settings, s, true)
	if err != nil {
		return nil, err
	}
	return &Trigger{id: config.Id, settings: s}, nil
}

// Metadata implements trigger.Factory.Metadata
func (*Factory) Metadata() *trigger.Metadata {
	return triggerMd
}

// Start implements util.Managed.Start
func (t *Trigger) Start() error {
	return t.server.Start()
}

// Stop implements util.Managed.Stop
func (t *Trigger) Stop() error {
	return t.server.Stop()
}

// Initialize trigger
func (t *Trigger) Initialize(ctx trigger.InitContext) error {
	log = ctx.Logger()
	log.Info(GetMessage(TriggerInitialize, t.id))
	router := httprouter.New()

	addr := ":" + strconv.Itoa(t.settings.Port)
	path := t.settings.Path
	gqlSchema := t.settings.GraphQLSchema

	// 1. Parse user schema into ast.Document
	astDoc, err := parser.Parse(parser.ParseParams{
		Source: gqlSchema,
		Options: parser.ParseOptions{
			NoLocation: true,
		},
	})

	if err != nil {
		return GetError(ParsingSchemaError, t.id, err.Error())
	}

	// 2. Build Graphql objects from ast.Document
	t.buildGraphqlTypes(astDoc)

	// 3. Build Graphql schema from ast.Document
	t.graphQLSchema, err = t.buildGraphqlSchema(astDoc, ctx.GetHandlers())

	if err != nil {
		return GetError(BuildingSchemaError, t.id, err.Error())
	}

	// 4. Setup GraphQL Server
	log.Info(GetMessage(StartingServer))
	t.server = NewServer(addr, router)
	t.server.secureConnection = t.settings.SecureConnection
	if t.server.secureConnection {
		t.server.serverKey = t.settings.ServerKey
		t.server.caCertificate = t.settings.CACertificate
	}

	// 5. Setup routes for the path & verb
	router.OPTIONS(path, handleCorsPreflight) // for CORS
	router.Handle("GET", path, newActionHandler(t))
	router.Handle("POST", path, newActionHandler(t))

	log.Info(GetMessage(ServerProperties, t.server.secureConnection, t.settings.Port, path))
	return nil
}

// TODO: Add support for custom Scalar type and custom Directives
// Builds an object for each type in the graphql schema and stores it in a type map.
func (t *Trigger) buildGraphqlTypes(doc *ast.Document) {
	log.Debug(GetMessage(ExecutingMethod, "buildGraphqlTypes"))
	t.gqlTypMap = make(map[string]graphql.Type)
	t.astIntfMap = make(map[string]*ast.InterfaceDefinition)
	t.astUnionMap = make(map[string]*ast.UnionDefinition)

	for _, def := range doc.Definitions {
		switch def.GetKind() {
		case "InterfaceDefinition":
			intfNode := def.(*ast.InterfaceDefinition)
			intf := graphql.NewInterface(
				graphql.InterfaceConfig{
					Name: intfNode.Name.Value,
				})
			t.gqlTypMap[intf.Name()] = intf
			t.astIntfMap[intf.Name()] = intfNode
		case "ObjectDefinition":
			objNode := def.(*ast.ObjectDefinition)
			obj := graphql.NewObject(
				graphql.ObjectConfig{
					Name: objNode.Name.Value,
				})
			t.gqlTypMap[obj.Name()] = obj
		case "UnionDefinition":
			// not creating graphql.NewUnion(), since Types and ResolveType are mandatory fields to provide
			unionNode := def.(*ast.UnionDefinition)
			t.astUnionMap[unionNode.Name.Value] = unionNode
		case "InputObjectDefinition":
			inputObjNode := def.(*ast.InputObjectDefinition)
			inputObj := graphql.NewInputObject(
				graphql.InputObjectConfig{
					Name: inputObjNode.Name.Value,
				})
			t.gqlTypMap[inputObj.Name()] = inputObj
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
			t.gqlTypMap[enum.Name()] = enum
		case "SchemaDefinition":
			t.foundSchemaElement = true
			sNode := def.(*ast.SchemaDefinition)
			for _, od := range sNode.OperationTypes {
				if od.Operation == "query" {
					t.rootQueryName = od.Type.Name.Value
				} else if od.Operation == "mutation" {
					t.rootMutationName = od.Type.Name.Value
				}
			}
		}
	}
	t.fillFieldsAndInterfaces(doc)
}

// Once the base types are parsed - fill in the fields and interfaces for each object and interface type
// This step is separated to allow for fields to have the same parent type.
func (t *Trigger) fillFieldsAndInterfaces(doc *ast.Document) {
	log.Debug(GetMessage(ExecutingMethod, "fillFieldsAndInterfaces"))
	t.astObjFieldDef = make(map[string][]*ast.FieldDefinition) // collects list of fields for each Object type
	t.astIntfImpl = make(map[string][]*ast.ObjectDefinition)   // collects list of implementations(objects) for each interface type
	t.gqlUnionTypes = make(map[string][]*graphql.Object)       // collects list of objects in a union type

	// do interfaces first
	for _, intfNode := range t.astIntfMap {
		intf := t.gqlTypMap[intfNode.Name.Value]
		intf = graphql.NewInterface(
			graphql.InterfaceConfig{
				Name:        intfNode.Name.Value,
				Fields:      t.getFields(intfNode.Fields),
				ResolveType: t.interfaceAndUnionResolver(),
				Description: GetAstStringValue(intfNode.Description),
			})
		t.gqlTypMap[intf.Name()] = intf
	}

	for _, def := range doc.Definitions {
		if def.GetKind() == "ObjectDefinition" {
			objNode := def.(*ast.ObjectDefinition)
			obj := t.gqlTypMap[objNode.Name.Value].(*graphql.Object)
			obj = graphql.NewObject(
				graphql.ObjectConfig{
					Name:        objNode.Name.Value,
					Fields:      t.getFields(objNode.Fields),
					Interfaces:  t.getInterfaces(objNode),
					Description: GetAstStringValue(objNode.Description),
				})
			t.gqlTypMap[obj.Name()] = obj
			t.astObjFieldDef[obj.Name()] = objNode.Fields
		} else if def.GetKind() == "InputObjectDefinition" {
			inputObjNode := def.(*ast.InputObjectDefinition)
			inputObj := t.gqlTypMap[inputObjNode.Name.Value].(*graphql.InputObject)
			inputObj = graphql.NewInputObject(
				graphql.InputObjectConfig{
					Name:        inputObjNode.Name.Value,
					Fields:      t.getInputFields(inputObjNode.Fields),
					Description: GetAstStringValue(inputObjNode.Description),
				})
			t.gqlTypMap[inputObj.Name()] = inputObj
		}
	}

	// do unions last
	for _, unionNode := range t.astUnionMap {
		union := graphql.NewUnion(
			graphql.UnionConfig{
				Name:        unionNode.Name.Value,
				Types:       t.getUnionTypes(unionNode.Types),
				ResolveType: t.interfaceAndUnionResolver(),
			})
		t.gqlTypMap[union.Name()] = union
		t.gqlUnionTypes[union.Name()] = union.Types()
	}
	t.fixSelfRefereningTypes(doc)
}

// Re-add all the fields to interfaces and objects to fix self referencing types. This will ensure all types contain parents fields.
func (t *Trigger) fixSelfRefereningTypes(doc *ast.Document) {
	log.Debug(GetMessage(ExecutingMethod, "fixSelfRefereningTypes"))
	for _, def := range doc.Definitions {
		if def.GetKind() == "InterfaceDefinition" {
			intfNode := def.(*ast.InterfaceDefinition)
			intf := t.gqlTypMap[intfNode.Name.Value].(*graphql.Interface)
			for _, fd := range intfNode.Fields {
				intf.AddFieldConfig(fd.Name.Value, &graphql.Field{
					Name:        fd.Name.Value,
					Type:        CoerceType(fd.Type, t.gqlTypMap),
					Description: GetAstStringValue(fd.Description),
				})
			}
		} else if def.GetKind() == "ObjectDefinition" {
			objNode := def.(*ast.ObjectDefinition)
			obj := t.gqlTypMap[objNode.Name.Value].(*graphql.Object)
			for _, fd := range objNode.Fields {
				obj.AddFieldConfig(fd.Name.Value, &graphql.Field{
					Name:        fd.Name.Value,
					Type:        CoerceType(fd.Type, t.gqlTypMap),
					Description: GetAstStringValue(fd.Description),
				})
			}
		}
	}
}

// Builds graphql.Fields from []ast.FieldDefinition
func (t *Trigger) getFields(astFields []*ast.FieldDefinition) graphql.Fields {
	fields := make(graphql.Fields)
	for _, fd := range astFields {
		fields[fd.Name.Value] = &graphql.Field{
			Name:        fd.Name.Value,
			Type:        CoerceType(fd.Type, t.gqlTypMap),
			Description: GetAstStringValue(fd.Description),
		}
	}
	return fields
}

// Builds graphql.InputObjectFieldConfigMap from []ast.InputValueDefinition
func (t *Trigger) getInputFields(astFields []*ast.InputValueDefinition) graphql.InputObjectConfigFieldMap {
	fields := make(graphql.InputObjectConfigFieldMap)
	for _, ivd := range astFields {
		fields[ivd.Name.Value] = &graphql.InputObjectFieldConfig{
			Type:         CoerceType(ivd.Type, t.gqlTypMap),
			DefaultValue: GetValue(ivd.DefaultValue),
			Description:  GetAstStringValue(ivd.Description),
		}
	}
	return fields
}

// Returns graphql.Interfaces for a given ast.ObjectDefinition
func (t *Trigger) getInterfaces(objNode *ast.ObjectDefinition) []*graphql.Interface {
	astIntfs := objNode.Interfaces
	intfs := []*graphql.Interface{}
	for _, ai := range astIntfs {
		if t.gqlTypMap[ai.Name.Value] != nil {
			t.astIntfImpl[ai.Name.Value] = append(t.astIntfImpl[ai.Name.Value], objNode)
			intfs = append(intfs, t.gqlTypMap[ai.Name.Value].(*graphql.Interface))
		}
	}
	return intfs
}

// Returns list of Object types for a given union type
func (t *Trigger) getUnionTypes(astUnionTypes []*ast.Named) []*graphql.Object {
	unionTypes := []*graphql.Object{}
	for _, ut := range astUnionTypes {
		if _, ok := t.gqlTypMap[ut.Name.Value]; ok {
			unionTypes = append(unionTypes, t.gqlTypMap[ut.Name.Value].(*graphql.Object))
		}
	}
	return unionTypes
}

// Interface and Union resolver to determine what concrete type the value passed from flow is.
func (t *Trigger) interfaceAndUnionResolver() graphql.ResolveTypeFn {
	return func(p graphql.ResolveTypeParams) *graphql.Object {
		log.Debug(GetMessage(InterfaceUnionResolver, p.Value))
		possibleType := t.getPossibleType(p)
		if possibleType == "" {
			log.Error("Error finding concrete type for interface resolver")
			return nil
		}
		return t.gqlTypMap[possibleType].(*graphql.Object)
	}
}

// TODO: Need to find better way to determine concrete type
// Compares the fields of data with all implementations(objects) of the interface and returns the first matching value
func (t *Trigger) getPossibleType(p graphql.ResolveTypeParams) string {
	outputType := GetInterfaceOrUnionType(p.Info.ReturnType)
	objNodes := []*graphql.Object{}
	if _, ok := t.astIntfImpl[outputType.Name()]; ok {
		// output type is a interface -- get list of *graphql.Object from ast.ObjectDefinition
		objDefNodes := t.astIntfImpl[outputType.Name()]
		for _, odn := range objDefNodes {
			if on, ok := t.gqlTypMap[odn.Name.Value]; ok {
				objNodes = append(objNodes, on.(*graphql.Object))
			}
		}
	} else {
		// output type is a union -- get list of *graphql.Object
		objNodes = t.gqlUnionTypes[outputType.Name()]
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
func (t *Trigger) buildGraphqlSchema(doc *ast.Document, handlers []trigger.Handler) (*graphql.Schema, error) {
	log.Debug(GetMessage(ExecutingMethod, "buildGraphqlSchema"))
	// if "schema" element does not exist, use default names for query and mutation
	if !t.foundSchemaElement {
		t.rootQueryName = "Query"
		t.rootMutationName = "Mutation"
	}

	queryType := t.buildArgsAndResolvers(t.rootQueryName, "Query", handlers)
	log.Debug(GetMessage(QueryType, queryType))
	mutationType := t.buildArgsAndResolvers(t.rootMutationName, "Mutation", handlers)
	log.Debug(GetMessage(MutationType, mutationType))

	typesArr := []graphql.Type{}
	for key, typ := range t.gqlTypMap {
		if key != t.rootQueryName && key != t.rootMutationName {
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
func (t *Trigger) buildArgsAndResolvers(targetOperationName string, operationType string, handlers []trigger.Handler) *graphql.Object {
	if fieldDefArr, ok := t.astObjFieldDef[targetOperationName]; ok {
		gqlFields := make(graphql.Fields)
		var handlerFound bool
		for _, fd := range fieldDefArr {
			args := make(graphql.FieldConfigArgument) // array of args
			for _, a := range fd.Arguments {
				args[a.Name.Value] = &graphql.ArgumentConfig{
					DefaultValue: GetValue(a.DefaultValue),
					Description:  GetAstStringValue(a.Description),
					Type:         CoerceType(a.Type, t.gqlTypMap),
				}
			}
			for _, handler := range handlers {
				hs := &HandlerSettings{}
				metadata.MapToStruct(handler.Settings(), hs, true)
				if strings.EqualFold(hs.ResolverFor, fd.Name.Value) && strings.EqualFold(hs.Operation, operationType) {
					handlerFound = true
					gqlFields[fd.Name.Value] = &graphql.Field{
						Args:        args,
						Name:        fd.Name.Value,
						Description: GetAstStringValue(fd.Description),
						Type:        CoerceType(fd.Type, t.gqlTypMap),
						Resolve:     fieldResolver(handler), // The flow to call when the query/mutation field is requested
					}
				}
			}
		}
		if !handlerFound {
			// if no flow found for query or mutation operation --> return nil
			return nil
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
func fieldResolver(handler trigger.Handler) graphql.FieldResolveFn {
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

		log.Debug(GetMessage(FlowReturnValue, flowReturnValue))

		replyDataObj, err := coerce.ToObject(flowReturnValue["data"])
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
	log.Debug(GetMessage(CORSPreFlight, r))
	c := cors.New(corsPrefix, log)
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
func newActionHandler(rt *Trigger) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		log.Debug(GetMessage(ReceivedRequest, rt.id))
		c := cors.New(corsPrefix, log)
		c.WriteCorsActualRequestHeaders(w)

		// get request options
		reqOpts, err := getRequestOptions(r)

		if err != nil {
			log.Error(GetMessage(ErrorProcessingRequest, err.Error()))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Debug(GetMessage(GraphQLRequest, *reqOpts))
		// Process the request
		result := graphql.Do(graphql.Params{
			OperationName:  reqOpts.OperationName,
			RequestString:  reqOpts.Query,
			Schema:         *rt.graphQLSchema,
			VariableValues: reqOpts.Variables,
		})

		log.Debug(GetMessage(GraphQLResponse, result))

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
