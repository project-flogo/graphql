---
title: GraphQL
weight: 4706
---
# tibco-graphql
This trigger serves as a GraphQL HTTP endpoint. You can pass in GraphQL queries via `GET` and `POST` requests.

## Installation

```bash
flogo install github.com/project-flogo/graphql/trigger/graphql
```

## Schema
Settings, Outputs and Endpoint:

```json
    "settings": [
      {
        "name": "port",
        "type": "integer",
        "required": true
      },
      {
        "name": "graphqlSchema",
        "type": "string",
        "required": true
      },
      {
        "name": "path",
        "type": "string",
        "required" : true
      }
    ],
    "output": [
      {
        "name": "arguments",
        "type": "object"
      }
    ],
    "reply": [
      {
        "name": "data",
        "type": "object"
      }
    ],
    "handler": {
      "settings": [
        {
          "name": "resolverFor",
          "type": "string",
          "required" : true
        },
        {
         "name": "operation",
         "type": "string",
         "required": false,
         "value": "Query",
         "allowed" : ["Query", "Mutation"]
       },
      ]
    }
```
## Settings
### Trigger:
| Setting     | Description    |
|:------------|:---------------|
| port | The port to listen on |         
| schema | The GraphQL schema |
| path | The HTTP resource path |
### Output:
| Setting     | Description    |
|:------------|:---------------|
| arguments      | The GraphQL operation arguments |
### Handler:
| Setting     | Description    |
|:------------|:---------------|
| resolverFor      | Indicates that this handler can resolve the specified GraphQL field. The value here must match a field from the schema. |
| operation | The GraphQL operation to support, Query and Mutation are the only valid option |

## Example GraphQL Types

```json
      
```

## Example GraphQL Schemas

```json
       
```

Note that if `user` and `address` are both to be resolvable, then a handler, which specifies `address` and `user` in the `resolverFor` field is required. Currently one Flogo action can be used to resolve a single GraphQL field, you may resolve as many fields as required with multiple handlers.

## Example Application

To build the example application, follow the steps below:

```bash
flogo create -f example.json
```

```bash
cd Example
flogo build
```

Now, run the application:

```bash
cd bin
./Example
```

To test the application, send a `GET` request:

```bash
curl -g 'http://localhost:7777/graphql?query={user(name:"Matt"){name,id},address{street,number}}'
```

The following response will be returned:

```json
{"data":{"address":{"number":"123","street":"Main St."},"user":{"id":"123","name":"Matt"}}}
```
