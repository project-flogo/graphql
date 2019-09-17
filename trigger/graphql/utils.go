package graphql

import (
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
)

// CoerceType converts ast.Type to graphql.Type
func CoerceType(typ ast.Type, typMap map[string]graphql.Type) graphql.Type {
	switch typ.GetKind() {
	case "Named":
		if IsScalarType(typ.(*ast.Named).Name.Value) {
			return CoerceScalarType(typ.(*ast.Named).Name.Value)
		}
		if t, ok := typMap[typ.(*ast.Named).Name.Value]; ok {
			return t
		}
		return nil
	case "List":
		return &graphql.List{
			OfType: CoerceType(typ.(*ast.List).Type, typMap),
		}
	case "NonNull":
		return &graphql.NonNull{
			OfType: CoerceType(typ.(*ast.NonNull).Type, typMap),
		}
	}
	return nil
}

// IsScalarType returns true for scalar types
func IsScalarType(t string) bool {
	switch t {
	case "Int", "String", "Float", "Boolean", "ID":
		return true
	default:
		return false
	}
}

// CoerceScalarType converts type to graphql.Scalar
func CoerceScalarType(typ string) *graphql.Scalar {
	switch typ {
	case "String":
		return graphql.String
	case "Float":
		return graphql.Float
	case "Int":
		return graphql.Int
	case "Boolean":
		return graphql.Boolean
	case "ID":
		return graphql.ID
	}
	return nil
}

// GetInterfaceOrUnionType returns the interface or union type from a given Output type
func GetInterfaceOrUnionType(typ graphql.Output) graphql.Type {
	switch typ.(type) {
	case *graphql.Interface:
		return typ.(*graphql.Interface)
	case *graphql.Union:
		return typ.(*graphql.Union)
	case *graphql.List:
		return GetInterfaceOrUnionType(typ.(*graphql.List).OfType)
	case *graphql.NonNull:
		return GetInterfaceOrUnionType(typ.(*graphql.NonNull).OfType)
	}
	return nil
}

// GetValue returns value of ast.Value
func GetValue(val ast.Value) interface{} {
	if val != nil {
		return val.GetValue()
	}
	return nil
}

// GetAstStringValue returns string value of ast.StringValue object
func GetAstStringValue(val interface{}) string {
	if val, ok := val.(ast.StringValue); ok {
		return val.Value
	}
	return ""
}
