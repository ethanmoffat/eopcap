package dump

import (
	"encoding/json"
	"io"
	"os"
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
	Value        string         `json:"value,omitempty"`    // The property's value (if not a struct/switch case).
	Children     []DumpProperty `json:"children,omitempty"` // The children of the property (if a struct/switch case).
}

func (dm *DumpModel) Marshal(filepath string) (err error) {
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
