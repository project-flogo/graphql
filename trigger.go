package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"net/http"

	"github.com/graphql-go/graphql"
	"github.com/julienschmidt/httprouter"
	"github.com/project-flogo/core/data/metadata"
	"github.com/project-flogo/core/support/log"
	"github.com/project-flogo/core/trigger"
)

var triggerMd = trigger.NewMetadata(&Settings{}, &HandlerSettings{}, &Output{}, &Reply{})

func init() {
	trigger.Register(&Trigger{}, &Factory{})
}

// Trigger GraphQL trigger struct
type Trigger struct {
	server   *Server
	settings *Settings
	id       string
	logger   log.Logger
}

type Factory struct {
}

// Metadata implements trigger.Factory.Metadata
func (*Factory) Metadata() *trigger.Metadata {
	return triggerMd
}

// New implements trigger.Factory.New
func (*Factory) New(config *trigger.Config) (trigger.Trigger, error) {
	s := &Settings{}
	err := metadata.MapToStruct(config.Settings, s, true)
	if err != nil {
		return nil, err
	}

	return &Trigger{id: config.Id, settings: s}, nil
}

var gqlObjects map[string]*graphql.Object
var graphQlSchema *graphql.Schema

func (t *Trigger) Initialize(ctx trigger.InitContext) error {
	t.logger = ctx.Logger()

	router := httprouter.New()
	addr := ":" + strconv.Itoa(t.settings.Port)

	// Build the GraphQL Object Types & Schemas
	t.buildGraphQLObjects()

	// Get the handlers
	handlers := ctx.GetHandlers()

	// Build the schema from the definition and bind to each handler
	var err error
	graphQlSchema, err = t.buildGraphQLSchema(&handlers)
	if err != nil {
		return err
	}

	// Setup routes for the path & verb
	router.Handle("GET", t.settings.Path, newActionHandler(t))
	router.Handle("POST", t.settings.Path, newActionHandler(t))

	ctx.Logger().Debugf("Configured on port %v", t.settings.Port)
	t.server = NewServer(addr, router)

	return nil
}

func (t *Trigger) buildGraphQLObjects() {
	gqlTypes := t.settings.Types

	// Create type objects
	gqlObjects = make(map[string]*graphql.Object)

	// Get the graphql types
	for _, typ := range gqlTypes {
		lTyp := lower(typ)
		typ := lTyp.(map[string]interface{})
		name := typ["name"].(string)
		fields := make(graphql.Fields)

		for k, f := range typ["fields"].(map[string]interface{}) {
			fTyp := f.(map[string]interface{})

			fields[k] = &graphql.Field{
				Type: coerceType(fTyp["type"].(string)),
			}
		}

		obj := graphql.NewObject(
			graphql.ObjectConfig{
				Name:   name,
				Fields: fields,
			})

		gqlObjects[name] = obj
	}
}

func (t *Trigger) buildGraphQLSchema(handlers *[]trigger.Handler) (*graphql.Schema, error) {
	fSchema := t.settings.Schema
	fSchema = lower(fSchema).(map[string]interface{})

	// Build the graphql schema
	var schema graphql.Schema
	var queryType *graphql.Object

	if strings.EqualFold(t.settings.Operation, "query") {

		var objName string
		queryFields := make(graphql.Fields)

		// Get the object name
		for k, v := range fSchema["query"].(map[string]interface{}) {
			if strings.EqualFold(k, "name") {
				objName = v.(string)
			} else if strings.EqualFold(k, "fields") {
				qf := v.(map[string]interface{})

				for k, v := range qf {

					// Grab query args
					argObj := v.(map[string]interface{})
					args := make(graphql.FieldConfigArgument)

					for k, v := range argObj["args"].(map[string]interface{}) {

						argTyp := v.(map[string]interface{})
						args[k] = &graphql.ArgumentConfig{
							Type: coerceType(argTyp["type"].(string)),
						}
					}

					for _, handler := range *handlers {
						s := &HandlerSettings{}
						err := metadata.MapToStruct(handler.Settings(), s, true)
						if err != nil {
							return nil, err
						}

						if strings.EqualFold(s.ResolverFor, k) {
							t.logger.Debugf("Found handler for field %v resolution...", k)

							// Build the queryField
							queryFields[k] = &graphql.Field{
								Type:    gqlObjects[k],
								Args:    args,
								Resolve: fieldResolver(handler),
							}
						}
					}
				}
			}
		}

		queryType = graphql.NewObject(
			graphql.ObjectConfig{
				Name:   objName,
				Fields: queryFields,
			})
	}

	schema, _ = graphql.NewSchema(
		graphql.SchemaConfig{
			Query: queryType,
		})

	return &schema, nil
}

func (t *Trigger) Start() error {
	return t.server.Start()
}

// Stop implements util.Managed.Stop
func (t *Trigger) Stop() error {
	return t.server.Stop()
}

func fieldResolver(handler trigger.Handler) graphql.FieldResolveFn {

	return func(p graphql.ResolveParams) (interface{}, error) {

		triggerData := &Output{
			Args: p.Args,
		}

		results, err := handler.Handle(context.Background(), triggerData)

		// Parse the reply from the action
		reply := &Reply{}
		reply.FromMap(results)

		return reply.Data, err
	}

}

func newActionHandler(rt *Trigger) httprouter.Handle {

	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

		rt.logger.Infof("Received request for id '%v'", rt.id)

		queryValues := r.URL.Query()
		queryParams := make(map[string]string, len(queryValues))
		header := make(map[string]string, len(r.Header))

		for key, value := range r.Header {
			header[strings.ToLower(key)] = strings.Join(value, ",")
		}

		for key, value := range queryValues {
			queryParams[strings.ToLower(key)] = strings.Join(value, ",")
		}

		var query string

		httpVerb := strings.ToUpper(r.Method)
		if val, ok := queryParams["query"]; ok && strings.EqualFold(httpVerb, "GET") {
			query = val
		} else if strings.EqualFold(httpVerb, "POST") {
			// Check the HTTP Header Content-Type
			contentType := r.Header.Get("Content-Type")
			if !strings.EqualFold(contentType, "application/json") {
				err := fmt.Errorf("%v", "Invalid content type. Must be application/json for POST methods.")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var content interface{}
			err := json.NewDecoder(r.Body).Decode(&content)
			if err != nil {
				switch {
				case err == io.EOF:
					// empty body
					//todo should handler say if content is expected?
				case err != nil:
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			jsonContent := content.(map[string]interface{})
			query = jsonContent["query"].(string)
		} else {
			err := fmt.Errorf("%v", "HTTP GET and POST are the only supported verbs.")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Process the request
		result := graphql.Do(graphql.Params{
			Schema:        *graphQlSchema,
			RequestString: query,
		})

		if len(result.Errors) > 0 {
			rt.logger.Errorf("GraphQL Trigger Error: %#v", result.Errors)
		}

		if result != nil {
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(http.StatusOK)

			if err := json.NewEncoder(w).Encode(result); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error(err)
			}
		}
	}
}

//
// Utility Functions
//
func coerceType(typ string) *graphql.Scalar {
	switch typ {
	case "graphql.String":
		return graphql.String
	case "graphql.Float":
		return graphql.Float
	case "graphql.Int":
		return graphql.Int
	case "graphql.Boolean":
		return graphql.Boolean
	}

	return nil
}

func lower(f interface{}) interface{} {
	switch f := f.(type) {
	case []interface{}:
		for i := range f {
			f[i] = lower(f[i])
		}
		return f
	case map[string]interface{}:
		lf := make(map[string]interface{}, len(f))
		for k, v := range f {
			lf[strings.ToLower(k)] = lower(v)
		}
		return lf
	default:
		return f
	}
}
