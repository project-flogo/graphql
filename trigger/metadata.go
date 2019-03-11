package trigger

type Settings struct {
	Port      int                    `md:"port,required"`
	Types     []interface{}          `md:"types,required"`
	Schema    map[string]interface{} `md:"schema,required"`
	Operation string                 `md:"operation,allowed(QUERY)"`
	Path      string                 `md:"path,required"`
}

type HandlerSettings struct {
	ResolverFor string `md:"resolverFor,required"`
}

type Output struct {
	Args interface{} `md:"args"`
}

func (o *Output) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"args": o.Args,
	}
}

func (o *Output) FromMap(values map[string]interface{}) error {
	o.Args = values["args"]

	return nil
}

type Reply struct {
	Data interface{} `md:"data"`
}

func (r *Reply) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"data": r.Data,
	}
}

func (r *Reply) FromMap(values map[string]interface{}) error {

	r.Data, _ = values["data"]

	return nil
}
