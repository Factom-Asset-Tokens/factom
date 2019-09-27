// MIT License
//
// Copyright 2018 Canonical Ledgers, LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

package factom_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/Factom-Asset-Tokens/factom"
	"github.com/stretchr/testify/assert"
)

var rcdUnmarshalBinaryTests = []struct {
	Name    string
	Data    []byte
	Error   string
	RCDType uint64
	Address *Bytes32
}{
	{
		Name: "valid",
		Data: NewBytesFromString(
			"010fd93026041de6387d2dcef0917c06288e690fa7652c20f044746e787b06b2bd"),
		RCDType: 1,
		Address: NewBytes32FromString("304d80538e27505d44d5ff0ada6a9d420d93a9994da75f0763c12c827b616668"),
	},
	{
		Name: "invalid (too short)",
		Data: NewBytesFromString(
			""),
		Error: "insufficient length",
	},
	{
		Name: "invalid (too short)",
		Data: NewBytesFromString(
			"010fd93026041de6387d2dcef0917c06288e690fa7652c20f044746e787b06b2"),
		Error: "insufficient length",
	},
	{
		Name: "invalid (unsupported rcd type)",
		Data: NewBytesFromString(
			"000fd93026041de6387d2dcef0917c06288e690fa7652c20f044746e787b06b2bd"),
		Error: "rcd version 0 unsupported",
	},
	{
		Name: "invalid (unsupported rcd type)",
		Data: NewBytesFromString(
			"020fd93026041de6387d2dcef0917c06288e690fa7652c20f044746e787b06b2bd"),
		Error: "rcd version 2 unsupported",
	},
}

func TestDecodeRCD(t *testing.T) {
	for _, test := range rcdUnmarshalBinaryTests {
		t.Run("UnmarshalBinary/"+test.Name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			rcd, r, err := DecodeRCD(test.Data)
			if len(test.Error) == 0 {
				require.NoError(err)
				require.Equal(r, len(test.Data))
				require.NotNil(rcd)

				assert.Equal(rcd.Type(), test.RCDType)
				addr, err := rcd.Address()
				require.NoError(err)
				assert.Equal(addr, test.Address)
			} else {
				require.EqualError(err, test.Error)
			}
		})
	}

	// To ensure there is not panics and all errors are caught
	t.Run("UnmarshalBinary/RCD", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			d := make([]byte, rand.Intn(500))
			rand.Read(d)

			rcd, read, err := DecodeRCD(d)
			if err == nil {
				// The RCD 1 type is pretty easy to be randomly valid.
				// So if it is type one and we read the right number of bytes,
				// there is no expected error.
				if read != 33 && rcd.Type() != 1 && d[0] == 0x01 {
					t.Errorf("expected an error")
				}
			}
		}
	})
}
