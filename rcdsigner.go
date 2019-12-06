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
	"crypto/ed25519"
	"fmt"
)

// TODO: What would be the best naming for this constants?
const (
	// Flags are set to indicate which rcds are valid for the validate
	// function. This allows a whitelist of valid rcd types for
	// the validate function. The flags are a bitmask to be combined with
	// a bitwise OR, e.g:
	//		R_RCD1|R_RCDe
	//

	R_ALL = 1 << iota // Indicates all rcd types are valid
	R_RCD1
)

// RCDSigner is the interface implemented by types that can generate Redeem
// Condition Datastructures and the corresponding signatures to validate them.
type RCDSigner interface {
	// RCD constructs the RCD.
	RCD() []byte

	// Sign the msg.
	Sign(msg []byte) []byte
}

func ValidateRCD(rcd, sig, msg []byte, flag int) (Bytes32, error) {
	if len(rcd) < 1 {
		return Bytes32{}, fmt.Errorf("invalid RCD size")
	}
	var validateRCD func(rcd, sig, msg []byte) (Bytes32, error)

	// Validate the rcd type is an accepted type based on the flag.
	// If `mask & flag` > 0, the rcd is enabled.
	// We always check the R_ALL bit
	mask := R_ALL

	switch rcd[0] {
	case RCDType01:
		// Also check the rcd01 bit
		mask = mask | R_RCD1
		validateRCD = ValidateRCD01
	default:
		return Bytes32{}, fmt.Errorf("unsupported RCD")
	}

	if flag&mask == 0 {
		return Bytes32{}, fmt.Errorf("rcd type is rejected by the validate mask")
	}
	return validateRCD(rcd, sig, msg)
}

const (
	// RCDType is the magic number identifying the currenctly accepted RCD.
	RCDType01 byte = 0x01
	// RCDSize is the size of the RCD.
	RCDType01Size = ed25519.PublicKeySize + 1
	// SignatureSize is the size of the ed25519 signatures.
	RCDType01SigSize = ed25519.SignatureSize
)

func ValidateRCD01(rcd, sig, msg []byte) (Bytes32, error) {
	if len(rcd) != RCDType01Size {
		return Bytes32{}, fmt.Errorf("invalid RCD size")
	}
	if rcd[0] != RCDType01 {
		return Bytes32{}, fmt.Errorf("invalid RCD type")
	}
	if len(sig) != RCDType01SigSize {
		return Bytes32{}, fmt.Errorf("invalid signature size")
	}

	pubKey := []byte(rcd[1:]) // Omit RCD Type byte
	if !ed25519.Verify(pubKey, msg, sig) {
		return Bytes32{}, fmt.Errorf("invalid signature")
	}

	return sha256d(rcd), nil
}
