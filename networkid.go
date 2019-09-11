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

package factom

import (
	"fmt"
	"strings"
)

var (
	mainnetID  = [...]byte{0xFA, 0x92, 0xE5, 0xA2}
	testnetID  = [...]byte{0x88, 0x3e, 0x09, 0x3b}
	localnetID = [...]byte{0xFA, 0x92, 0xE5, 0xA4}
)

func MainnetID() NetworkID  { return mainnetID }
func TestnetID() NetworkID  { return testnetID }
func LocalnetID() NetworkID { return localnetID }

type NetworkID [4]byte

func (n NetworkID) String() string {
	switch n {
	case mainnetID:
		return "mainnet"
	case testnetID:
		return "testnet"
	case localnetID:
		return "localnet"
	default:
		return "custom: 0x" + Bytes(n[:]).String()
	}
}
func (n *NetworkID) Set(netIDStr string) error {
	switch strings.ToLower(netIDStr) {
	case "main", "mainnet":
		*n = mainnetID
	case "test", "testnet":
		*n = testnetID
	case "local", "localnet":
		*n = localnetID
	default:
		if netIDStr[:2] == "0x" {
			// omit leading 0x
			netIDStr = netIDStr[2:]
		}
		var b Bytes
		if err := b.Set(netIDStr); err != nil {
			return err
		}
		if len(b) != len(n[:]) {
			return fmt.Errorf("invalid length")
		}
		copy(n[:], b)
	}
	return nil
}

func (n NetworkID) IsMainnet() bool {
	return n == mainnetID
}

func (n NetworkID) IsTestnet() bool {
	return n == testnetID
}

func (n NetworkID) IsLocalnet() bool {
	return n == localnetID
}

func (n NetworkID) IsCustom() bool {
	return !n.IsMainnet() && !n.IsTestnet()
}
