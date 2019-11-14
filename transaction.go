package factom

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/Factom-Asset-Tokens/factom/varintf"
)

type FactoidTransaction struct {
	// TODO: The header is usually at the top level, is this ok?
	FactoidTransactionHeader

	FCTInputs  []FactoidTransactionIO
	FCTOutputs []FactoidTransactionIO
	ECOutputs  []FactoidTransactionIO
	Signatures []FactoidTransactionSignature
}

type FactoidTransactionHeader struct {
	// TransactionID is not in the marshalled binary
	TransactionID *Bytes32

	Version uint64
	// TimestampSalt is accurate to the millisecond
	TimestampSalt time.Time
}

// factoidTransactionIOs is used as a wrapper for an array of IOs to reuse the
// functionality. This is compared to writing your own loop to handle
// lists of io behavior.
type factoidTransactionIOs []FactoidTransactionIO

type FactoidTransactionIO struct {
	Amount uint64
	// Address can be an SHA256d(RCD) for FCT in/out, or a public key for EC out.
	// It is the encoded bytes into the human readable addresses
	Address Bytes32
}

type FactoidTransactionSignature struct {
	// SHA256d(RCD) == FactoidIOAddress for the inputs
	ReedeemCondition RCD1
	SignatureBlock   Bytes
}

// IsPopulated returns true if f has already been successfully populated by a
// call to Get. IsPopulated returns false if f.FCTInputs, or f.Signatures are
// nil, or if f.Timestamp is zero.
func (f FactoidTransaction) IsPopulated() bool {
	return f.FCTInputs != nil && // This array should not be nil
		f.Signatures != nil &&
		!f.TimestampSalt.IsZero()
}

// IsPopulated returns true if s has already been successfully populated by a
// call to Get. IsPopulated returns false if s.SignatureBlock or
// s.ReedeemCondition are nil
func (s FactoidTransactionSignature) IsPopulated() bool {
	return s.SignatureBlock != nil
}

// Valid returns if the inputs of the factoid transaction are properly signed
// by the redeem conditions. It will also validate the total inputs is greater
// than the total outputs.
func (f *FactoidTransaction) Valid() bool {
	if !f.IsPopulated() {
		return false
	}

	// Validate amounts
	if f.TotalFCTInputs() < f.TotalFCTOutputs()+f.TotalECOutput() {
		return false
	}

	// Validate signatures
	if len(f.FCTInputs) != len(f.Signatures) {
		return false
	}

	msg, err := f.MarshalLedgerBinary()
	if err != nil {
		return false
	}

	for i := range f.FCTInputs {
		expAddr := f.Signatures[i].ReedeemCondition.Address()

		// RCD should match the input
		if bytes.Compare(expAddr[:], f.FCTInputs[i].Address[:]) != 0 {
			return false
		}

		if !f.Signatures[i].Validate(msg) {
			return false
		}
	}

	return true
}

func (f *FactoidTransaction) TotalFCTInputs() (total uint64) {
	return factoidTransactionIOs(f.FCTInputs).TotalAmount()
}

func (f *FactoidTransaction) TotalFCTOutputs() (total uint64) {
	return factoidTransactionIOs(f.FCTOutputs).TotalAmount()
}

// TotalECOutput is delimated in factoishis
func (f *FactoidTransaction) TotalECOutput() (total uint64) {
	return factoidTransactionIOs(f.ECOutputs).TotalAmount()
}

func (s factoidTransactionIOs) TotalAmount() (total uint64) {
	for _, io := range s {
		total += io.Amount
	}
	return
}

func (s FactoidTransactionSignature) Validate(msg Bytes) bool {
	return s.ReedeemCondition.Validate(msg, s.SignatureBlock)
}

// Get queries factomd for the entry corresponding to f.TransactionID, which
// must be not nil. After a successful call all inputs, outputs, and
// the header will be populated
func (f *FactoidTransaction) Get(ctx context.Context, c *Client) error {
	// TODO: Test this functionality
	// If the TransactionID is nil then we have nothing to query for.
	if f.TransactionID == nil {
		return fmt.Errorf("txid is nil")
	}
	// If the Transaction is already populated then there is nothing to do. If
	// the Hash is nil, we cannot populate it anyway.
	if f.IsPopulated() {
		return nil
	}

	params := struct {
		Hash *Bytes32 `json:"hash"`
	}{Hash: f.TransactionID}
	var result struct {
		Data Bytes `json:"data"`
	}
	if err := c.FactomdRequest(ctx, "raw-data", params, &result); err != nil {
		return err
	}

	if err := f.UnmarshalBinary(result.Data); err != nil {
		return err
	}

	return nil
}

// ComputeTransactionID computes the txid for a given transaction. The txid is
// the sha256 of the ledger fields in a factoid transaction. The ledger fields
// exclude the signature block of the transaction
func (f *FactoidTransaction) ComputeTransactionID() (Bytes32, error) {
	data, err := f.MarshalLedgerBinary()
	if err != nil {
		return Bytes32{}, err
	}

	return f.computeTransactionID(data)
}

func (f *FactoidTransaction) computeTransactionID(ledgerBinary Bytes) (Bytes32, error) {
	txid := Bytes32(sha256.Sum256(ledgerBinary))
	return txid, nil
}

// ComputeFullHash computes the fullhash for a given transaction. The fullhash
// is the sha256 of all the fields in a factoid transaction.
func (f *FactoidTransaction) ComputeFullHash() (*Bytes32, error) {
	data, err := f.MarshalBinary()
	if err != nil {
		return nil, err
	}

	txid := Bytes32(sha256.Sum256(data))
	return &txid, nil
}

// MarshalLedgerBinary marshals the transaction ledger fields to their
// binary representation. This excludes the signature blocks
func (f *FactoidTransaction) MarshalLedgerBinary() ([]byte, error) {
	// TODO: More checks up front?
	if !f.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	// It's very difficult to know the size before marshaling, as
	// each in/out has a varint so make the buffer at the end

	// The header bytes
	header, err := f.MarshalHeaderBinary()
	if err != nil {
		return nil, err
	}

	// Inputs
	inputs, err := factoidTransactionIOs(f.FCTInputs).MarshalBinary()
	if err != nil {
		return nil, err
	}

	// FCT Outputs
	fctout, err := factoidTransactionIOs(f.FCTOutputs).MarshalBinary()
	if err != nil {
		return nil, err
	}

	// EC Outputs
	ecout, err := factoidTransactionIOs(f.ECOutputs).MarshalBinary()
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(header)+len(inputs)+len(fctout)+len(ecout))
	var i int
	i += copy(data[i:], header)
	i += copy(data[i:], inputs)
	i += copy(data[i:], fctout)
	i += copy(data[i:], ecout)

	return data, nil
}

// TODO: Re-eval how to do this. Kinda different from the rest
func (f *FactoidTransaction) MarshalBinary() ([]byte, error) {
	// TODO: More checks up front?
	if !f.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	data, err := f.MarshalLedgerBinary()
	if err != nil {
		return nil, err
	}

	for _, s := range f.Signatures {
		sig, err := s.MarshalBinary()
		if err != nil {
			return nil, err
		}
		data = append(data, sig...)
	}

	return data, nil
}

// MarshalHeaderBinary marshals the transaction's header to its binary
// representation. See UnmarshalHeaderBinary for encoding details.
func (f *FactoidTransaction) MarshalHeaderBinary() ([]byte, error) {
	version := varintf.Encode(f.Version)
	data := make([]byte, TransactionHeadMinLen+len(version))
	var i int
	i += copy(data[i:], version)

	// Do the timestamp as 6 bytes in ms
	ms := f.TimestampSalt.UnixNano() / 1e6
	buf := bytes.NewBuffer(make([]byte, 0, 8))
	if err := binary.Write(buf, binary.BigEndian, ms); err != nil {
		return nil, err
	}
	i += copy(data[i:], buf.Bytes()[2:])

	data[i] = uint8(len(f.FCTInputs))
	i += 1
	data[i] = uint8(len(f.FCTOutputs))
	i += 1
	data[i] = uint8(len(f.ECOutputs))
	i += 1
	return data, nil
}

// MarshalBinary marshals a set of transaction ios to its binary representation.
// See UnmarshalBinary for encoding details.
func (ios factoidTransactionIOs) MarshalBinary() ([]byte, error) {
	var data []byte
	for _, io := range ios {
		iodata, err := io.MarshalBinary()
		if err != nil {
			return nil, err
		}
		data = append(data, iodata...)
	}
	return data, nil
}

// MarshalBinary marshals a transaction io to its binary representation.
// See UnmarshalBinary for encoding details.
func (io *FactoidTransactionIO) MarshalBinary() ([]byte, error) {
	amount := varintf.Encode(io.Amount)
	data := make([]byte, 32+len(amount))
	var i int
	i += copy(data[i:], amount)
	i += copy(data[i:], io.Address[:])
	return data, nil
}

// MarshalBinary marshals a transaction signature to its binary representation.
// See UnmarshalBinary for encoding details.
func (s *FactoidTransactionSignature) MarshalBinary() ([]byte, error) {
	if !s.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	rcdData, err := s.ReedeemCondition.MarshalBinary()
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(rcdData)+len(s.SignatureBlock))
	var i int
	i += copy(data[i:], rcdData)
	i += copy(data[i:], s.SignatureBlock)
	return data, nil
}

const (
	TransactionHeadMinLen = 0 + // Version length is varint
		6 + // timestamp
		1 + // input count
		1 + // factoid output count
		1 // EC output count

	TransactionTotalMinLen = TransactionHeadMinLen // Coinbases have no body

)

// Decode will consume as many bytes as necessary to unmarshal the factoid
// transaction. It will return the number of bytes read and an error.
func (f *FactoidTransaction) Decode(data []byte) (i int, err error) {
	if len(data) < TransactionTotalMinLen {
		return 0, fmt.Errorf("insufficient length")
	}

	// Decode header
	version, i := varintf.Decode(data)
	if i < 0 {
		return 0, fmt.Errorf("version bytes invalid")
	}
	f.Version = version

	msdata := make([]byte, 8)
	// TS + counts length check
	if len(data) < i+(6+3) {
		return 0, fmt.Errorf("not enough bytes to decode tx")
	}
	copy(msdata[2:], data[i:i+6])
	ms := binary.BigEndian.Uint64(msdata)
	f.TimestampSalt = time.Unix(0, int64(ms)*1e6)
	i += 6
	inputCount := uint8(data[i])
	i += 1
	fctOutputCount := uint8(data[i])
	i += 1
	ecOutputCount := uint8(data[i])
	i += 1

	// Decode the body

	// Decode the inputs
	f.FCTInputs = make([]FactoidTransactionIO, inputCount)
	read, err := factoidTransactionIOs(f.FCTInputs).Decode(data[i:])
	if err != nil {
		return 0, err
	}
	i += read

	// Decode the FCT Outputs
	f.FCTOutputs = make([]FactoidTransactionIO, fctOutputCount)
	read, err = factoidTransactionIOs(f.FCTOutputs).Decode(data[i:])
	if err != nil {
		return 0, err
	}
	i += read

	// Decode the EC Outputs
	f.ECOutputs = make([]FactoidTransactionIO, ecOutputCount)
	read, err = factoidTransactionIOs(f.ECOutputs).Decode(data[i:])
	if err != nil {
		return 0, err
	}
	i += read

	// All data minus the signatures is the needed binary data to compute
	// the txid
	ledgerData := data[:i]

	// Decode the signature blocks, one per input
	f.Signatures = make([]FactoidTransactionSignature, len(f.FCTInputs))
	for c := uint8(0); c < uint8(len(f.FCTInputs)); c++ {
		// f.Signatures[i] = new(FactoidTransactionSignature)
		read, err := f.Signatures[c].Decode(data[i:])
		if err != nil {
			return 0, err
		}
		i += read
	}

	txid, err := f.computeTransactionID(ledgerData)
	if err != nil {
		return 0, err
	}

	// If the txid is already set, validate the txid
	if f.TransactionID != nil {
		if *f.TransactionID != txid {
			return 0, fmt.Errorf("invalid txid")
		}
	}

	f.TransactionID = &txid

	return i, err
}

// UnmarshalBinary unmarshals the data into a factoid transaction.
func (f *FactoidTransaction) UnmarshalBinary(data []byte) error {
	// TODO: Some length checks to prevent too few/too many bytes
	_, err := f.Decode(data)
	return err
}

// Decode takes a given input and decodes the set of bytes needed to populate
// the set of factoid transactions ios. The set length should be preset before
// calling this function. It will return how many bytes it read and return an error.
func (ios factoidTransactionIOs) Decode(data []byte) (int, error) {
	var i int
	for c := range ios {
		read, err := ios[c].Decode(data[i:])
		if err != nil {
			return 0, err
		}

		i += read
	}

	return i, nil
}

// Decode takes a given input and decodes the set of bytes needed for a full
// transaction input/output. It will return how many bytes it read and an error.
// A FactoidTransactionIO includes an amount and an address.
func (io *FactoidTransactionIO) Decode(data []byte) (int, error) {
	amount, i := varintf.Decode(data)
	if i < 0 {
		return 0, fmt.Errorf("amount is not a valid varint")
	}
	io.Amount = amount

	if len(data)-i < 32 {
		return 0, fmt.Errorf("not enough bytes to decode factoidtx")
	}
	var tmp Bytes32 // TODO: Fix this
	copy(tmp[:], data[i:i+32])
	io.Address = tmp
	i += 32

	return i, nil
}

// Decode will take a given input and decode the set of bytes needed for the full
// FactoidTransactionSignature. It will return how many bytes it read and an error.
// A FactoidTransactionSignature includes the RCD type and it's signature block.
func (s *FactoidTransactionSignature) Decode(data []byte) (int, error) {
	rcd, i, err := DecodeRCD(data)
	if err != nil {
		return 0, err
	}

	// TODO: How do you want to handle this? Have the decode only return the
	// 	concrete rcd1 type?
	rcd1, ok := rcd.(*RCD1)
	if !ok {
		return -1, fmt.Errorf("rcd %d type not supported", rcd.Type())
	}
	s.ReedeemCondition = *rcd1

	s.SignatureBlock = make([]byte, rcd.SignatureBlockSize())
	i += copy(s.SignatureBlock, data[i:])

	return i, nil
}
