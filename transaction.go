package factom

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/Factom-Asset-Tokens/factom/varintf"
)

type FactoidTransaction struct {
	// TODO: The header is usually at the top level, is this ok?
	FactoidTransactionHeader

	FCTInputs  []FactoidTransactionIO        `json:"inputs"`
	FCTOutputs []FactoidTransactionIO        `json:"fctoutputs"`
	ECOutputs  []FactoidTransactionIO        `json:"ecoutputs"`
	Signatures []FactoidTransactionSignature `json:"signatures"`
}

type FactoidTransactionHeader struct {
	// TransactionID is not in the marshalled binary
	TransactionID *Bytes32 `json:"txid"`

	Version uint64 `json:"version"`
	// Timestamp is accurate to the millisecond
	Timestamp time.Time `json:"timestamp"`

	InputCount     uint8 `json:"inputcount"`
	FCTOutputCount uint8 `json:"fctoutcount"`
	ECOutputCount  uint8 `json:"ecoutcount"`
}

type FactoidTransactionIOs []FactoidTransactionIO

type FactoidTransactionIO struct {
	Amount uint64 `json:"amount"`
	// Address can be an SHA256d(RCD) for FCT in/out, or a public key for EC out.
	// It is the encoded bytes into the human readable addresses
	Address *Bytes32 `json:"address"`
}

type FactoidTransactionSignature struct {
	// SHA256d(RCD) == FactoidIOAddress for the inputs
	ReedeemCondition RCD   `json:"rcd"`
	SignatureBlock   Bytes `json:"amount"`
}

// IsPopulated returns true if f has already been successfully populated by a
// call to Get. IsPopulated returns false if f.FCTInputs, or f.Signatures are
// nil, or if f.Timestamp is zero.
func (f FactoidTransaction) IsPopulated() bool {
	return f.FCTInputs != nil && // Although a coinbase has 0 inputs, this array should not be nil
		f.Signatures != nil &&
		f.Timestamp != time.Time{}
}

// IsPopulated returns true if io has already been successfully populated by a
// call to Get. IsPopulated returns false if io.Address is nil
func (io FactoidTransactionIO) IsPopulated() bool {
	return io.Address != nil
}

// IsPopulated returns true if s has already been successfully populated by a
// call to Get. IsPopulated returns false if s.SignatureBlock or s.ReedeemCondition are nil
func (s FactoidTransactionSignature) IsPopulated() bool {
	return s.SignatureBlock != nil &&
		s.ReedeemCondition != nil
}

// Valid returns if the inputs of the factoid transaction are properly signed by the redeem conditions.
// It will also validate the total inputs is greater than the total outputs.
func (s *FactoidTransaction) Valid() bool {
	if !s.IsPopulated() {
		return false
	}

	// Validate amounts
	if s.TotalFCTInputs() < s.TotalFCTOutputs()+s.TotalECOutput() {
		return false
	}

	// Validate signatures
	if len(s.FCTInputs) != len(s.Signatures) {
		return false
	}

	msg, err := s.MarshalLedgerBinary()
	if err != nil {
		return false
	}

	for i := range s.FCTInputs {
		expAddr, err := s.Signatures[i].ReedeemCondition.Address()
		if err != nil {
			return false
		}
		// RCD should match the input
		if bytes.Compare(expAddr[:], s.FCTInputs[i].Address[:]) != 0 {
			return false
		}

		if !s.Signatures[i].Validate(msg) {
			return false
		}
	}

	return true
}

func (s *FactoidTransaction) TotalFCTInputs() (total uint64) {
	return FactoidTransactionIOs(s.FCTInputs).TotalAmount()
}

func (s *FactoidTransaction) TotalFCTOutputs() (total uint64) {
	return FactoidTransactionIOs(s.FCTOutputs).TotalAmount()
}

// TotalECOutput is delimated in factoishis
func (s *FactoidTransaction) TotalECOutput() (total uint64) {
	return FactoidTransactionIOs(s.ECOutputs).TotalAmount()
}

func (s FactoidTransactionIOs) TotalAmount() (total uint64) {
	for _, io := range s {
		total += io.Amount
	}
	return
}

func (s FactoidTransactionSignature) Validate(msg Bytes) bool {
	return s.ReedeemCondition.Validate(msg, s.SignatureBlock)
}

// Get queries factomd for the entry corresponding to f.TransactionID, which must be not
// nil. After a successful call all inputs, outputs, and the header will be populated
func (f *FactoidTransaction) Get(c *Client) error {
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
	requestTxId := f.TransactionID

	params := struct {
		Hash *Bytes32 `json:"hash"`
	}{Hash: f.TransactionID}
	var result struct {
		Data Bytes `json:"data"`
	}
	if err := c.FactomdRequest("raw-data", params, &result); err != nil {
		return err
	}

	if err := f.UnmarshalBinary(result.Data); err != nil {
		return err
	}

	txid, err := f.ComputeTransactionID()
	if err != nil {
		return err
	}
	if txid != *requestTxId {
		return fmt.Errorf("invalid txid")
	}

	return nil
}

// ComputeTransactionID computes the txid for a given transaction. The txid is the sha256 of
// the ledger fields in a factoid transaction. The ledger fields exclude the signature block of
// the transaction
func (f *FactoidTransaction) ComputeTransactionID() (Bytes32, error) {
	data, err := f.MarshalLedgerBinary()
	if err != nil {
		return Bytes32{}, err
	}

	txid := Bytes32(sha256.Sum256(data))
	return txid, nil
}

// ComputeFullHash computes the fullhash for a given transaction. The fullhash is the sha256 of all
// the fields in a factoid transaction.
func (f *FactoidTransaction) ComputeFullHash() (*Bytes32, error) {
	data, err := f.MarshalBinary()
	if err != nil {
		return nil, err
	}

	txid := Bytes32(sha256.Sum256(data))
	return &txid, nil
}

// MarshalLedgerBinary marshals the transaction ledger fields to their binary representation.
// This excludes the signature blocks
func (f *FactoidTransaction) MarshalLedgerBinary() ([]byte, error) {
	// TODO: More checks up front?
	if !f.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	// It's very difficult to know the size before marshaling, as each in/out has a varint
	// so make the buffer at the end

	// The header bytes
	header, err := f.MarshalHeaderBinary()
	if err != nil {
		return nil, err
	}

	// Inputs
	inputs, err := FactoidTransactionIOs(f.FCTInputs).MarshalBinary()
	if err != nil {
		return nil, err
	}

	// FCT Outputs
	fctout, err := FactoidTransactionIOs(f.FCTOutputs).MarshalBinary()
	if err != nil {
		return nil, err
	}

	// EC Outputs
	ecout, err := FactoidTransactionIOs(f.ECOutputs).MarshalBinary()
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

// MarshalHeaderBinary marshals the transaction's header to its binary representation. See
// UnmarshalHeaderBinary for encoding details.
func (f *FactoidTransaction) MarshalHeaderBinary() ([]byte, error) {
	version := varintf.Encode(f.Version)
	data := make([]byte, TransactionHeadMinLen+len(version))
	var i int
	i += copy(data[i:], version)

	// Do the timestamp as 6 bytes in ms
	ms := f.Timestamp.UnixNano() / 1e6
	buf := bytes.NewBuffer(make([]byte, 0, 8))
	if err := binary.Write(buf, binary.BigEndian, ms); err != nil {
		return nil, err
	}
	i += copy(data[i:], buf.Bytes()[2:])

	data[i] = f.InputCount
	i += 1
	data[i] = f.FCTOutputCount
	i += 1
	data[i] = f.ECOutputCount
	i += 1
	return data, nil
}

// MarshalBinary marshals a set of transaction ios to its binary representation. See
// UnmarshalBinary for encoding details.
func (ios FactoidTransactionIOs) MarshalBinary() ([]byte, error) {
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

// MarshalBinary marshals a transaction io to its binary representation. See
// UnmarshalBinary for encoding details.
func (io *FactoidTransactionIO) MarshalBinary() ([]byte, error) {
	if !io.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	amount := varintf.Encode(io.Amount)
	data := make([]byte, 32+len(amount))
	var i int
	i += copy(data[i:], amount)
	i += copy(data[i:], io.Address[:])
	return data, nil
}

// MarshalBinary marshals a transaction signature to its binary representation. See
// UnmarshalBinary for encoding details.
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
	// Because the length of an FactoidTransaction is hard to define up front, we will catch
	// any sort of out of bound errors in a recover
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to unmarshal")
		}
	}()

	if len(data) < TransactionTotalMinLen {
		return 0, fmt.Errorf("insufficient length")
	}

	// Decode header
	i, err = f.DecodeHeader(data)
	if err != nil {
		return 0, err
	}

	// Decode the inputs
	f.FCTInputs = make([]FactoidTransactionIO, f.InputCount)
	read, err := FactoidTransactionIOs(f.FCTInputs).Decode(data[i:])
	if err != nil {
		return 0, err
	}
	i += read

	// Decode the FCT Outputs
	f.FCTOutputs = make([]FactoidTransactionIO, f.FCTOutputCount)
	read, err = FactoidTransactionIOs(f.FCTOutputs).Decode(data[i:])
	if err != nil {
		return 0, err
	}
	i += read

	// Decode the EC Outputs
	f.ECOutputs = make([]FactoidTransactionIO, f.ECOutputCount)
	read, err = FactoidTransactionIOs(f.ECOutputs).Decode(data[i:])
	if err != nil {
		return 0, err
	}
	i += read

	// Decode the signature blocks, one per input
	f.Signatures = make([]FactoidTransactionSignature, f.InputCount)
	for c := uint8(0); c < f.InputCount; c++ {
		// f.Signatures[i] = new(FactoidTransactionSignature)
		read, err := f.Signatures[c].Decode(data[i:])
		if err != nil {
			return 0, err
		}
		i += read
	}

	txid, err := f.ComputeTransactionID()
	if err != nil {
		return 0, err
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

func (f *FactoidTransaction) DecodeHeader(data []byte) (int, error) {
	version, i := varintf.Decode(data)
	f.Version = version

	msdata := make([]byte, 8)
	copy(msdata[2:], data[i:i+6])
	ms := binary.BigEndian.Uint64(msdata)
	f.Timestamp = time.Unix(0, int64(ms)*1e6)
	i += 6
	f.InputCount = data[i]
	i += 1
	f.FCTOutputCount = data[i]
	i += 1
	f.ECOutputCount = data[i]
	i += 1

	return i, nil
}

// Decode takes a given input and decodes the set of bytes needed to populate
// the set of factoid transactions ios. The set length should be preset before
// calling this function. It will return how many bytes it read and return an error.
func (ios FactoidTransactionIOs) Decode(data []byte) (int, error) {
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
	io.Amount = amount
	io.Address = NewBytes32(data[i : i+32])
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
	s.ReedeemCondition = rcd
	s.SignatureBlock = make([]byte, rcd.SignatureBlockSize())
	i += copy(s.SignatureBlock, data[i:])

	return i, nil
}
