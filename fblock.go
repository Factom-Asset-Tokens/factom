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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/Factom-Asset-Tokens/factom/varintf"
)

// FBlock represents a Factom Factoid Block
type FBlock struct {
	// Computed Fields
	KeyMR       *Bytes32
	LedgerKeyMR *Bytes32

	// Header Fields
	BodyMR          *Bytes32
	PrevKeyMR       *Bytes32
	PrevLedgerKeyMR *Bytes32

	ExchangeRate uint64
	Height       uint32

	// ExpansionBytes is the expansion space in the fblock. If we do not
	// understand the expansion, we just store the raw bytes
	ExpansionBytes Bytes

	// Number of bytes contained in the body
	bodySize uint32

	// Body Fields
	Transactions []FactoidTransaction

	// Other fields
	//
	// End of Minute transaction heights.  The mark the height of the first
	// tx index of the NEXT period.  This tx may not exist.  The Coinbase
	// transaction is considered to be in the first period.  Factom's
	// periods will initially be a minute long, and there will be
	// 10 of them.  This may change in the future.
	endOfPeriod [10]int
}

// IsPopulated returns true if fb has already been successfully populated by a
// call to Get. IsPopulated returns false if fb.Transactions is nil.
func (fb FBlock) IsPopulated() bool {
	return len(fb.Transactions) > 0 && // FBlocks always contain at least a coinbase
		fb.BodyMR != nil &&
		fb.PrevKeyMR != nil &&
		fb.PrevLedgerKeyMR != nil
}

// Get queries factomd for the Factoid Block at fb.Header.Height or fb.KeyMR.
// After a successful call, the Transactions will all be populated.
func (fb *FBlock) Get(c *Client) (err error) {
	if fb.IsPopulated() {
		return nil
	}

	if fb.KeyMR != nil {
		params := struct {
			Hash *Bytes32 `json:"hash"`
		}{Hash: fb.KeyMR}
		var result struct {
			Data Bytes `json:"data"`
		}
		if err := c.FactomdRequest(context.Background(), "raw-data", params, &result); err != nil {
			return err
		}
		return fb.UnmarshalBinary(result.Data)
	}

	params := struct {
		Height uint32 `json:"height"`
	}{fb.Height}
	result := struct {
		// We will ignore all the other fields, and just unmarshal from the raw.
		RawData Bytes `json:"rawdata"`
	}{}
	if err := c.FactomdRequest(context.Background(), "fblock-by-height", params, &result); err != nil {
		return err
	}

	return fb.UnmarshalBinary(result.RawData)
}

const (
	FBlockMinHeaderLen = 32 + // Factoid ChainID
		32 + // BodyMR
		32 + // PrevKeyMR
		32 + // PrevLedgerKeyMR
		8 + // EC Exchange Rate
		4 + // DB Height
		0 + // Header Expansion size (varint)
		0 + // Header Expansion Area (Min 0)
		4 + // Transaction Count
		4 // Body Size

	FBlockMinTotalLen = FBlockMinHeaderLen
)

const (
	// Minute markers indicate at which minute in the block the
	// factoid transactions were processed.
	FBlockMinuteMarker = 0x00
)

// UnmarshalBinary unmarshals raw directory block data.
//
// Header
//      [Factoid Block ChainID (Bytes32{31:0x0f})] +
//      [BodyMR (Bytes32)] +
//      [PrevKeyMR (Bytes32)] +
//      [PrevLedgerKeyMR (Bytes32)] +
//      [Exchange Rate (8 bytes)] +
//      [DB Height (4 bytes)] +
//      [Header Expansion size (Bytes)] +
//      [Header Expansion Area (Bytes)] +
//      [Transaction Count (4 bytes)] +
//      [Body Size (4 bytes)] +
//
// Body
//      [Tx 0 (Bytes)] +
//      ... +
//      [Tx N (Bytes)] +
//
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#factoid-block
func (fb *FBlock) UnmarshalBinary(data []byte) (err error) {
	if len(data) < FBlockMinTotalLen {
		return fmt.Errorf("insufficient length")
	}

	expFChain := FBlockChainID()
	if bytes.Compare(data[:32], expFChain[:]) != 0 {
		return fmt.Errorf("invalid factoid chainid")
	}

	i := 32

	fb.BodyMR = new(Bytes32)
	i += copy(fb.BodyMR[:], data[i:])

	fb.PrevKeyMR = new(Bytes32)
	i += copy(fb.PrevKeyMR[:], data[i:])

	fb.PrevLedgerKeyMR = new(Bytes32)
	i += copy(fb.PrevLedgerKeyMR[:], data[i:])

	fb.ExchangeRate = binary.BigEndian.Uint64(data[i : i+8])
	i += 8

	fb.Height = binary.BigEndian.Uint32(data[i : i+4])
	i += 4

	expansionSize, read := varintf.Decode(data[i:])
	if read < 0 {
		return fmt.Errorf("expansion size is not a valid varint")
	}
	i += read

	// sanity check, if the expansion size is greater than all the data we
	// have, then the expansion size was bogus.
	if expansionSize > uint64(len(data)) {
		return fmt.Errorf("expansion size is too large at %d bytes, "+
			"when only %d bytes exist", expansionSize, len(data))
	}

	// This should be a safe cast to int, as the size is never > max int
	// For these type assertions to fail on a 32 bit system, we would need a
	// 4gb factoid block.
	fb.ExpansionBytes = make([]byte, expansionSize)
	if uint64(len(data[i:])) < expansionSize {
		return fmt.Errorf("expansion size is %d, only %d bytes exist", expansionSize, len(data[i:]))
	}
	copy(fb.ExpansionBytes, data[i:])
	i += int(expansionSize)

	// Check the next two slice accesses won't be out of bounds
	if len(data[i:]) < 8 {
		return fmt.Errorf("ran out of bytes")
	}

	txCount := binary.BigEndian.Uint32(data[i : i+4])
	i += 4
	fb.bodySize = binary.BigEndian.Uint32(data[i : i+4])
	i += 4

	// Check the txcount is at least somewhat reasonable. This check
	// is not perfect, given txs are variable in size.
	if uint64(len(data[i:])) < uint64(txCount)*TransactionTotalMinLen {
		return fmt.Errorf("not enough bytes")
	}

	// Header is all data we've read so far
	headerHash := sha256.Sum256(data[:i])
	bodyMRElements := make([][]byte, int(txCount)+len(fb.endOfPeriod))
	bodyLedgerMRElements := make([][]byte, int(txCount)+len(fb.endOfPeriod))

	fb.Transactions = make([]FactoidTransaction, txCount)
	var period int
	for c := range fb.Transactions {
		// Before each fct tx, we need to see if there is a marker byte that
		// indicates a minute marker
		for data[i] == FBlockMinuteMarker {
			if period > len(fb.endOfPeriod) {
				return fmt.Errorf("too many minute markers")
			}
			fb.endOfPeriod[period] = c
			bodyMRElements[c+period] = []byte{FBlockMinuteMarker}
			bodyLedgerMRElements[c+period] = []byte{FBlockMinuteMarker}
			period++ // The next period encountered will be the next minute
			i += 1
		}

		read, err := fb.Transactions[c].Decode(data[i:])
		if err != nil {
			return err
		}

		// Append the elements for MR calculation
		bodyMRElements[c+period] = data[i : i+read]
		// Calc the signature size
		var sigSize int
		for _, o := range fb.Transactions[c].Signatures {
			sigSize += o.ReedeemCondition.Length() + o.ReedeemCondition.SignatureBlockSize()
		}
		bodyLedgerMRElements[c+period] = data[i : i+(read-sigSize)]

		i += read
	}

	// Finish the minute markers
	for period < len(fb.endOfPeriod) {
		period++
		idx := int(txCount) + period - 1
		bodyMRElements[idx] = []byte{FBlockMinuteMarker}
		bodyLedgerMRElements[idx] = []byte{FBlockMinuteMarker}
	}

	// If we have not hit the end of our periods, a single byte will remain
	for period < len(fb.endOfPeriod) {
		fb.endOfPeriod[period] = int(txCount)
		period++ // The next period encountered will be the next minute
		i += 1
	}

	// Merkle Root Calculations
	bodyMR, err := ComputeFBlockBodyMR(bodyMRElements)
	if err != nil {
		return err
	}

	bodyLedgerMR, err := ComputeFBlockBodyMR(bodyLedgerMRElements)
	if err != nil {
		return err
	}

	// Set out computed fields
	keyMr, err := ComputeFBlockKeyMR([][]byte{headerHash[:], bodyMR[:]})
	if err != nil {
		return err
	}
	ledgerMr, err := ComputeFBlockKeyMR([][]byte{bodyLedgerMR[:], headerHash[:]})
	if err != nil {
		return err
	}

	// Already set, check it matches
	if fb.KeyMR != nil {
		if keyMr != *fb.KeyMR {
			return fmt.Errorf("invalid keymr")
		}
	}

	fb.KeyMR = &keyMr
	fb.LedgerKeyMR = &ledgerMr

	return nil
}

func (fb *FBlock) MarshalBinary() ([]byte, error) {
	// Header has variable size
	header, err := fb.MarshalBinaryHeader() // This checks for populated
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(header)+int(fb.bodySize))

	var i int
	i += copy(data[i:], header)

	var period int
	for c, transaction := range fb.Transactions {
		for period < len(fb.endOfPeriod) && // If minute marked remain to be written
			fb.endOfPeriod[period] > 0 && // If the period markers are actually set (ignore otherwise)
			c == fb.endOfPeriod[period] { // This TX is the market point
			data[i] = FBlockMinuteMarker
			i += 1
			period++
		}

		tData, err := transaction.MarshalBinary()
		if err != nil {
			return nil, err
		}
		i += copy(data[i:], tData)
	}

	for period < len(fb.endOfPeriod) {
		data[i] = FBlockMinuteMarker
		i += 1
		period++
	}

	return data, nil
}

func (fb *FBlock) MarshalBinaryHeader() ([]byte, error) {
	if !fb.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	expansionSize := varintf.Encode(uint64(len(fb.ExpansionBytes)))
	data := make([]byte, FBlockMinHeaderLen+len(expansionSize)+len(fb.ExpansionBytes))
	var i int
	fBlockChain := FBlockChainID()
	i += copy(data[i:], fBlockChain[:])
	i += copy(data[i:], fb.BodyMR[:])
	i += copy(data[i:], fb.PrevKeyMR[:])
	i += copy(data[i:], fb.PrevLedgerKeyMR[:])

	binary.BigEndian.PutUint64(data[i:], fb.ExchangeRate)
	i += 8
	binary.BigEndian.PutUint32(data[i:], fb.Height)
	i += 4
	i += copy(data[i:], expansionSize)
	// Currently all expansion bytes are stored in the ExpansionBytes.
	i += copy(data[i:], fb.ExpansionBytes)
	binary.BigEndian.PutUint32(data[i:], uint32(len(fb.Transactions)))
	i += 4
	binary.BigEndian.PutUint32(data[i:], fb.bodySize)
	i += 4

	return data, nil
}

func (fb FBlock) ComputeFullHash() (Bytes32, error) {
	data, err := fb.MarshalBinary()
	if err != nil {
		return Bytes32{}, err
	}
	return sha256.Sum256(data), nil
}

func (fb FBlock) ComputeHeaderHash() (Bytes32, error) {
	header, err := fb.MarshalBinaryHeader()
	if err != nil {
		return Bytes32{}, err
	}
	return sha256.Sum256(header), nil
}
