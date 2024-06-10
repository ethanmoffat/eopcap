package dump

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/ethanmoffat/eolib-go/v3/protocol/net"
)

func Convert(data []byte, packet net.Packet) (model DumpModel, err error) {
	var family, action string
	if family, err = packet.Family().String(); err != nil {
		return
	}
	if action, err = packet.Action().String(); err != nil {
		return
	}

	model = DumpModel{
		Family:     family,
		Action:     action,
		Expected:   data,
		Properties: getChildrenFromStruct(reflect.ValueOf(packet)),
	}

	return
}

func getChildrenFromStruct(reflectValue reflect.Value) (properties []DumpProperty) {
	reflectType := reflectValue.Type()

	if reflectType.Kind() == reflect.Pointer || reflectType.Kind() == reflect.Interface {
		reflectType = reflectType.Elem()
		reflectValue = reflectValue.Elem()
	}

	for i := 0; i < reflectValue.NumField(); i++ {
		structField := reflectType.Field(i)
		structFieldValue := reflectValue.Field(i)

		if structField.Name == "byteSize" {
			continue
		}

		dumpProperty := DumpProperty{
			PropertyName: protocolPropertyName(structField.Name),
		}

		switch structFieldValue.Kind() {
		case reflect.Array:
			fallthrough
		case reflect.Slice:
			if structField.Type.Elem().Kind() == reflect.Uint8 {
				dumpProperty.TypeName = "[]byte"
				dumpProperty.Value = structFieldValue.Bytes()
			} else {
				dumpProperty.TypeName = "[]" + qualifiedName(structField.Type.Elem())
				for arrayNdx := 0; arrayNdx < structFieldValue.Len(); arrayNdx++ {
					nextChild := toArrayDumpProperty(structFieldValue.Index(arrayNdx))
					dumpProperty.Children = append(dumpProperty.Children, nextChild)
				}
			}
		case reflect.Interface:
			if structFieldValue.IsNil() || structFieldValue.Elem().IsNil() {
				continue
			}

			structFieldValue = structFieldValue.Elem()
			if structFieldValue.Kind() == reflect.Pointer {
				structFieldValue = structFieldValue.Elem()
			}
			dumpProperty.IsInterface = true
			fallthrough
		case reflect.Struct:
			dumpProperty.TypeName = qualifiedName(structFieldValue.Type())
			dumpProperty.Children = getChildrenFromStruct(structFieldValue)

		default:
			dumpProperty.TypeName = structFieldValue.Type().Name()
			dumpProperty.Optional, dumpProperty.Value = fieldValue(structFieldValue)
		}

		properties = append(properties, dumpProperty)
	}

	return
}

func fieldValue(structFieldValue reflect.Value) (optional bool, value any) {
	if structFieldValue.Kind() == reflect.Pointer {
		optional = true
		if structFieldValue.IsNil() {
			value = nil
			return
		}

		structFieldValue = structFieldValue.Elem()
	}

	switch structFieldValue.Kind() {
	case reflect.Int:
		value = structFieldValue.Int()
	case reflect.Bool:
		value = structFieldValue.Bool()
	case reflect.String:
		value = structFieldValue.String()
	default:
		value = "<unknown>: " + structFieldValue.Type().Name()
	}

	return
}

func toArrayDumpProperty(v reflect.Value) DumpProperty {
	switch v.Kind() {
	case reflect.Struct:
		return DumpProperty{
			TypeName: qualifiedName(v.Type()),
			Children: getChildrenFromStruct(v),
		}
	default:
		dp := DumpProperty{}
		dp.Optional, dp.Value = fieldValue(v)
		return dp
	}
}

func qualifiedName(t reflect.Type) string {
	pkg := t.PkgPath()
	name := t.Name()

	pkg = strings.Replace(pkg, "github.com/ethanmoffat/eolib-go/v3/", "", -1)

	if len(pkg) > 0 {
		return fmt.Sprintf("%s::%s", pkg, name)
	} else {
		return name
	}
}

func protocolPropertyName(goProperty string) string {
	output := strings.Builder{}

	for i, c := range goProperty {
		if unicode.IsUpper(c) && i > 0 {
			output.WriteRune('_')
		}
		output.WriteRune(unicode.ToLower(c))
	}

	return output.String()
}
