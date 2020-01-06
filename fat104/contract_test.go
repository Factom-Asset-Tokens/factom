package fat104

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

var testABIJSON = `
{
        "_add": {
                "args": [
                        "i32",
                        "i32"
                ],
                "return": "i32"
        }
}`

var testABI = ABI{"_add": Func{
	Args: []Type{TypeI32, TypeI32},
	Ret:  TypeI32},
}

func TestABI(t *testing.T) {
	require := require.New(t)
	var abi ABI
	require.NoError(json.Unmarshal([]byte(testABIJSON), &abi))
	require.Equal(testABI, abi)
}

var testMetadata = `{"author": "Adam"}`

var testContractJSON = `
{
        "metadata": ` + testMetadata + `,
        "abi": ` + testABIJSON + `
}`

var testContract = Contract{
	ABI:      testABI,
	Metadata: json.RawMessage(testMetadata),
}

func TestContract(t *testing.T) {
	require := require.New(t)
	var con Contract
	require.NoError(json.Unmarshal([]byte(testContractJSON), &con))
	require.Equal(testContract, con)
}
