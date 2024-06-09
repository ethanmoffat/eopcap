package dump

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"strings"
)

// DumpModel represents a dump of a deserialized packet object in the EO protocol.
type DumpModel struct {
	Family     string         `json:"family"`     // The family of the packet.
	Action     string         `json:"action"`     // The action of the packet.
	Expected   []byte         `json:"expected"`   // The expected data that the packet was deserialized from. Encoded as a base64 string.
	Properties []DumpProperty `json:"properties"` // The properties of the packet's object representation.
}

// DumpProperty represents a property in a dump model object.
//
// It contains PropertyName/Value mappings as well as an optional TypeName and Children.
//
// Arrays use DumpProperty by setting the TypeName to "[]T" (where T is the element type) and
// containing a list of children with their 'value' set to the values in the array. For complex
// objects (structs), the children of each element are set to the property name/value pairs for
// each member of the object.
type DumpProperty struct {
	TypeName     string         `json:"type,omitempty"`     // The type name of the property of the structure.
	PropertyName string         `json:"name,omitempty"`     // The name of the property.
	Value        any            `json:"value,omitempty"`    // The property's value (if not a struct/switch case).
	Optional     bool           `json:"optional,omitempty"` // Whether the field is optional or not
	Children     []DumpProperty `json:"children,omitempty"` // The children of the property (if a struct/switch case).

	IsInterface bool `json:"-"` // True if this is an interface object.
}

func (dm *DumpModel) Marshal(filepath string) (err error) {
	parts := strings.Split(filepath, "/")
	tmpPath := ""
	for i := range parts {
		if i != len(parts)-1 {
			tmpPath = path.Join(tmpPath, parts[i])
			_, err := os.Stat(tmpPath)
			if os.IsNotExist(err) {
				os.Mkdir(tmpPath, 0755)
			}
		}
	}

	if strings.HasSuffix(filepath, ".json") {
		filepath = strings.ReplaceAll(filepath, ".json", "")
	}

	interfaces := append([]string{filepath}, getInterfaceNames(dm)...)
	for i := range interfaces {
		if i != 0 {
			interfaces[i] = strings.Replace(interfaces[i], dm.Family+dm.Action, "", 1)
		}
	}
	filepath = strings.Join(interfaces, "_") + ".json"

	var f *os.File
	f, err = os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}

	defer f.Close()

	err = f.Truncate(0)
	if err != nil {
		return
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		return
	}

	var bytes []byte
	bytes, err = json.MarshalIndent(dm, "", "  ")
	if err != nil {
		return err
	}

	_, err = f.Write(bytes)
	return
}

func Unmarshal(filepath string) (dm DumpModel, err error) {
	var f *os.File
	f, err = os.Open(filepath)
	if err != nil {
		return
	}

	defer f.Close()

	var bytes []byte
	bytes, err = io.ReadAll(f)
	if err != nil {
		return
	}

	dm = DumpModel{}
	err = json.Unmarshal(bytes, &dm)
	return
}

func getInterfaceNames(dumpModel *DumpModel) (interfaceNames []string) {
	for _, p := range dumpModel.Properties {
		interfaceNames = append(interfaceNames, getInterfaceNamesFromProperty(p)...)
	}
	return
}

func getInterfaceNamesFromProperty(dumpProperty DumpProperty) (interfaceNames []string) {
	if dumpProperty.IsInterface {
		doubleColonIndex := strings.LastIndex(dumpProperty.TypeName, "::")

		if doubleColonIndex >= 0 && doubleColonIndex < len(dumpProperty.TypeName)+2 {
			sanitizedTypeName := string(dumpProperty.TypeName[doubleColonIndex+2:])
			interfaceNames = append(interfaceNames, sanitizedTypeName)
		}
	}

	for _, p := range dumpProperty.Children {
		interfaceNames = append(interfaceNames, getInterfaceNamesFromProperty(p)...)
	}
	return
}
