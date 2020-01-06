package fat104

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/Factom-Asset-Tokens/factom"
	"github.com/Factom-Asset-Tokens/factom/fat107"
)

type Contract struct {
	ABI      ABI             `json:"abi"`
	Metadata json.RawMessage `json:"metadata"`

	fat107.DataStore `json:"-"`
	Wasm             []byte `json:"-"`
}

func Lookup(ctx context.Context, c *factom.Client,
	chainID *factom.Bytes32) (Contract, error) {
	d, err := fat107.Lookup(ctx, c, chainID)
	if err != nil {
		return Contract{}, err
	}

	var con Contract
	if err := json.Unmarshal(d.Metadata, &con); err != nil {
		return Contract{}, err
	}

	con.DataStore = d

	return con, nil
}

func (con *Contract) Get(ctx context.Context, c *factom.Client) error {
	var wasm bytes.Buffer
	wasm.Grow(int(con.DataStore.Size))
	if err := con.DataStore.Get(ctx, c, &wasm); err != nil {
		return err
	}
	con.Wasm = wasm.Bytes()
	return nil
}

type ABI map[string]Func

type Func struct {
	Args []Type `json:"args,omitempty"`
	Ret  Type   `json:"return,omitempty"`
}

type Type int

const (
	TypeUndefined = iota
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
