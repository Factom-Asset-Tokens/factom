package fat104

import (
	"encoding/json"
	"fmt"
)

type ABI map[string]Func

type Func struct {
	Name string `json:"-"`
	Args []Type `json:"args,omitempty"`
	Ret  Type   `json:"return,omitempty"`
}

type Type int

const (
	TypeUndefined Type = iota
	TypeI32
	TypeI64
	TypeString
	TypeBytes
	TypeUnknown
)

func (t *Type) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "i32":
		*t = TypeI32
	case "i64":
		*t = TypeI64
	case "string":
		*t = TypeString
	case "bytes":
		*t = TypeBytes
	default:
		return fmt.Errorf("unknown fat104.Type")
	}
	return nil
}

func (t Type) MarshalJSON() ([]byte, error) {
	switch t {
	case TypeI32, TypeI64, TypeString, TypeBytes:
		return []byte(t.String()), nil
	default:
		return nil, fmt.Errorf("unknown fat104.Type")
	}
}

func (t Type) String() string {
	switch t {
	case TypeUndefined:
		return "TypeUndefined"
	case TypeI32:
		return "i32"
	case TypeI64:
		return "i64"
	case TypeString:
		return "string"
	case TypeBytes:
		return "bytes"
	default:
		return "TypeUnknown"
	}
}
