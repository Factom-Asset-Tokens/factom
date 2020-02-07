package fat104

import (
	"bytes"
	"context"
	"encoding/json"

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
