package dump

import (
	"fmt"
	"reflect"
	"strings"

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
			PropertyName: structField.Name,
		}

		switch structFieldValue.Kind() {
		case reflect.Array:
			fallthrough
		case reflect.Slice:
			dumpProperty.PropertyName = structField.Name
			dumpProperty.TypeName = "[]" + qualifiedName(structField.Type.Elem())
			for arrayNdx := 0; arrayNdx < structFieldValue.Len(); arrayNdx++ {
				nextChild := toArrayDumpProperty(structFieldValue.Index(arrayNdx))
				dumpProperty.Children = append(dumpProperty.Children, nextChild)
			}

		case reflect.Interface:
			structFieldValue = structFieldValue.Elem()
			if structFieldValue.Kind() == reflect.Pointer {
				structFieldValue = structFieldValue.Elem()
			}
			fallthrough
		case reflect.Struct:
			dumpProperty.TypeName = qualifiedName(structFieldValue.Type())
			dumpProperty.Children = getChildrenFromStruct(structFieldValue)

		default:
			dumpProperty.TypeName = structFieldValue.Type().Name()
			dumpProperty.Value = stringify(structFieldValue)
		}

		properties = append(properties, dumpProperty)
	}

	return
}

func stringify(structFieldValue reflect.Value) string {
	switch structFieldValue.Kind() {
	case reflect.Int:
		return fmt.Sprintf("%d", structFieldValue.Int())
	case reflect.Bool:
		return fmt.Sprintf("%v", structFieldValue.Bool())
	case reflect.String:
		return structFieldValue.String()
	}
	return "<unknown>: " + structFieldValue.Type().Name()
}

func toArrayDumpProperty(v reflect.Value) DumpProperty {
	switch v.Kind() {
	case reflect.Struct:
		return DumpProperty{
			TypeName: qualifiedName(v.Type()),
			Children: getChildrenFromStruct(v),
		}
	default:
		return DumpProperty{Value: stringify(v)}
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
