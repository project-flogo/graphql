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
        "name": "path",
        "type": "string",
        "required" : true
      },
      {
        "name": "secureConnection",
        "type": "boolean",
        "value": false
      },
      {
        "name": "serverKey",
        "type": "string"
      },
      {
        "name": "caCertificate",
        "type": "string"
      },
      {
        "name": "graphqlSchema",
        "type": "string",
        "required": true
      }
    ],
    "handler": {
      "settings": [
        {
         "name": "operation",
         "type": "string",
         "required": false,
         "value": "Query",
         "allowed" : ["Query", "Mutation"]
       },
       {
          "name": "resolverFor",
          "type": "string",
          "required" : true
        }
      ]
    },
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
    ]
```
## Settings
### Trigger:
| Setting          | Description    |
|:-----------------|:---------------|
| port             | The port to listen on |
| path             | The HTTP resource path |
| secureConnection | Set to "true" for a secure connection |
| serverKey        | A PEM encoded private key file |
| caCertificate    | A PEM encoded CA or Server certificate file |
| schema           | The GraphQL schema |

### Handler:
| Setting     | Description    |
|:------------|:---------------|
| operation   | The GraphQL operation to support, Query and Mutation are the only valid values |
| resolverFor | Indicates that this handler can resolve the specified GraphQL field. The value here must match a field from the schema. |

## Map to flow inputs
1. Create input parameter "arguments" of type "object" at action input/output settings.
2. In Map to flow inputs, map Trigger Output "arguments" of type "any" to Flow Input Params "arguments" of type "object"

## Map from flow output
1. Create output parameter "data" of type "object" at action input/output settings.
2. In Map from flow output, map Flow Output "data" of type "object" to Trigger Response "data" of type "any"


## Example GraphQL Schemas

```
type User {
    id: Int!
    name: String
    email: String
    address: Address
    phone: String
}

type Address {
    street: String
    suite: String
    city: String
    zipcode: String
}

type Query {
    GetUser(userId: Int): User
}

schema {
    query: Query
}
```
Note: When entering the schema into the text box field of Flogo Web OSS Studio, all the new lines("\n") need to be replaced by space(" ").
Currently one Flogo action can be used to resolve a single GraphQL field, you may resolve as many fields as required with multiple handlers.

## Example Application

To build the example application, follow the steps below:

```bash
flogo create -f example1.json
```

```bash
cd Example1
flogo build
```

Now, run the application:

```bash
cd bin
./Example1
```

To test the application, send a `GET` request:

```bash
curl -g 'http://localhost:7879/graphql?query={GetUser(userId:1){name,id},address{city,zipcode}}'
```

The following response will be returned:

```json
{"data": {"GetUser": {"address": {"city": "Gwenborough","zipcode": "92998-3874"},"id": 1,"name": "Leanne Graham"}}}
```
Additional example applications available under samples folder [here](https://github.com/project-flogo/graphql/tree/master/samples).
