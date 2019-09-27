package factom

import (
	"crypto/ed25519"
	"encoding"
	"fmt"

	"github.com/Factom-Asset-Tokens/factom/varintf"
)

// RCD is the underlying structure behind a factoid address. A factoid address is a sha256d(RCD).
// The most common and basic RCD type, is type 1. That being just a single public key that uses a single
// 64 byte signature block.
type RCD interface {
	// Type is varint encoded, but typically only uses 1 byte
	Type() uint64

	// SignatureBlockSize returns the expected size of the signature block
	// for a given RCD. This is not a constant for all RCD types.
	SignatureBlockSize() int

	// Address returns the sha256(rcd) that is the factoid address
	Address() (*Bytes32, error)

	Validate(msg Bytes, signature Bytes) bool

	// For Marshalling
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// DecodeRCD will decode any given data into it's respective RCD
// type. It will return the RCD, the number of bytes read, and an error.
// The details underlying format of the data can be seen on the UnmarshalBinary
// functions of the RCD types.
func DecodeRCD(data []byte) (reedemCondition RCD, read int, err error) {
	// TODO: The varintf decode function can panic
	//		until that is fixed, the only way to proctect the call is
	// 		to panic recover
	defer func() {
		// TODO: Remove this recover if the varintf ever gets a protected call
		//		that will prevent panics and instead hand out an error.
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to decode")
		}
	}()

	// Min 1 bytes for a varint of 1 byte
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("insufficient length")
	}

	version, _ := varintf.Decode(data)
	switch version {
	case 1:
		rcd := new(RCD1)
		if len(data) < RCDType1Len {
			return nil, 0, fmt.Errorf("insufficient length")
		}
		if err := rcd.UnmarshalBinary(data[:RCDType1Len]); err != nil {
			return nil, 0, err
		}
		return rcd, RCDType1Len, nil
	default:
		return nil, 0, fmt.Errorf("rcd version %d unsupported", version)
	}
}

// RCD1 is the simple rcd of a factoid address with a single public key.
// RCD1 contains the type and a single 32 byte ed25519 public key
type RCD1 struct {
	PublicKey *Bytes32
}

func (r *RCD1) Type() uint64 {
	return 1
}

func (r *RCD1) SignatureBlockSize() int {
	return 64 // 64 byte ed25519 sig
}

func (r *RCD1) Address() (*Bytes32, error) {
	data, err := r.MarshalBinary()
	if err != nil {
		return nil, err
	}
	addr := Bytes32(sha256d(data))
	return &addr, nil
}

func (r *RCD1) Validate(msg Bytes, signature Bytes) bool {
	// TODO: This library might not be doing cannonical ed25519 signature checking
	//		to ensure all signatures are on the correct side of the curve
	return ed25519.Verify(r.PublicKey[:], msg, signature)
}

// IsPopulated returns true if r has already been successfully populated by a
// call to Get. IsPopulated returns false if r.PublicKey is nil.
func (r *RCD1) IsPopulated() bool {
	return r.PublicKey != nil
}

// MarshalBinary marshals the rcd type to its binary representation. See
// UnmarshalBinary for encoding details.
func (r *RCD1) MarshalBinary() ([]byte, error) {
	if !r.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	data := make([]byte, RCDType1Len)
	data[0] = 1
	i := 1
	i += copy(data[i:], r.PublicKey[:])
	return data, nil
}

const (
	RCDType1Len = 1 + // [Version byte (0x01)]
		32 // Public key

)

// UnmarshalBinary unmarshals the raw rcd type data to the RCD1 struct.
//
// [Version byte (0x01)] +
// [ed25519 pubkey (32 bytes)] +
func (r *RCD1) UnmarshalBinary(data []byte) error {
	if len(data) != RCDType1Len {
		return fmt.Errorf("incorrect number of bytes")
	}

	if data[0] != 1 {
		return fmt.Errorf("wrong rcd type byte")
	}

	r.PublicKey = new(Bytes32)
	copy(r.PublicKey[:], data[1:])

	return nil
}
