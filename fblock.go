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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	merkle "github.com/AdamSLevy/go-merkle"
	"github.com/Factom-Asset-Tokens/factom/varintf"
)

const (
	FBlockMinuteMarker = 0x00
)

// FBlock represents a Factom Factoid Block
type FBlock struct {
	KeyMR       *Bytes32 `json:"keymr"`
	LedgerKeyMR *Bytes32 `json:"ledgerkeymr"`

	Header FBlockHeader `json:"header"`

	Transactions []*FactoidTransaction `json:"transactions"`

	// End of Minute transaction heights.  The mark the height of the first entry of
	// the NEXT period.  This entry may not exist.  The Coinbase transaction is considered
	// to be in the first period.  Factom's periods will initially be a minute long, and
	// there will be 10 of them.  This may change in the future.
	endOfPeriod [10]int
}

type FBlockHeader struct {
	BodyMR          *Bytes32 `json:"bodymr"`
	PrevKeyMR       *Bytes32 `json:"prevkeymr"`
	PrevLedgerKeyMR *Bytes32 `json:"prevkeymr"`

	ExchangeRate uint64 `json:"exchrate"`
	Height       uint32 `json:"dbheight"`

	// ExpansionBytes is the expansion space in the fblock. If we do not understand the
	// expansion, we just store the raw bytes
	ExpansionSize  int64 `json:"expansionsize"` // Stored as a varint
	ExpansionBytes Bytes `json:"expansiondata"`

	// Number of txs in the block
	TransactionCount uint32 `json:"txcount"`
	// Number of bytes contained in the body
	BodySize uint32 `json:"bodysize"`
}

// IsPopulated returns true if fb has already been successfully populated by a
// call to Get. IsPopulated returns false if fb.Transactions is nil.
func (fb FBlock) IsPopulated() bool {
	return len(fb.Transactions) > 0 && // FBlocks always contain at least a coinbase
		fb.Header.BodyMR != nil &&
		fb.Header.PrevKeyMR != nil && // TODO: Why not check the computed keymr?
		fb.Header.PrevLedgerKeyMR != nil
}

// Get queries factomd for the Factoid Block at fb.Header.Height or fb.KeyMR.
// After a successful call, the Transactions will all be populated.
func (fb *FBlock) Get(c *Client) (err error) {
	if fb.IsPopulated() {
		return nil
	}

	if fb.KeyMR != nil {
		orig := fb.KeyMR
		defer func() { // Ensure we got the block we asked for
			if err != nil {
				return
			}

			if fb.KeyMR != nil && *orig != *fb.KeyMR {
				err = fmt.Errorf("invalid key merkle root")
				return
			}
		}()

		params := struct {
			Hash *Bytes32 `json:"hash"`
		}{Hash: fb.KeyMR}
		var result struct {
			Data Bytes `json:"data"`
		}
		if err := c.FactomdRequest("raw-data", params, &result); err != nil {
			return err
		}
		return fb.UnmarshalBinary(result.Data)
	}

	params := struct {
		Height uint32 `json:"height"`
	}{fb.Header.Height}
	result := struct {
		// We will ignore all the other fields, and just unmarshal from the raw.
		RawData Bytes `json:"rawdata"`
	}{}
	if err := c.FactomdRequest("fblock-by-height", params, &result); err != nil {
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

// UnmarshalBinary unmarshals raw directory block data.
//
// Header
// [Factoid Block ChainID (Bytes32{31:0x0a})] +
// [BodyMR (Bytes32)] +
// [PrevKeyMR (Bytes32)] +
// [PrevLedgerKeyMR (Bytes32)] +
// [Exchange Rate (8 bytes)] +
// [DB Height (4 bytes)] +
// [Header Expansion size (Bytes)] +
// [Header Expansion Area (Bytes)] +
// [Transaction Count (4 bytes)] +
// [Body Size (4 bytes)] +
//
// Body
// [Tx 0 (Bytes)] +
// ... +
// [Tx N (Bytes)] +
//
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#factoid-block
func (fb *FBlock) UnmarshalBinary(data []byte) (err error) {
	// Because the length of an FBlock is hard to define up front, we will catch
	// any sort of out of bound errors in a recover
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to unmarshal")
		}
	}()

	// TODO: More length checks up front
	if len(data) < FBlockMinTotalLen {
		return fmt.Errorf("insufficient length")
	}

	if bytes.Compare(data[:32], factoidBlockChainID[:]) != 0 {
		return fmt.Errorf("invalid factoid chainid")
	}
	i := 32
	fb.Header.BodyMR = new(Bytes32)
	i += copy(fb.Header.BodyMR[:], data[i:i+len(fb.Header.BodyMR)])
	fb.Header.PrevKeyMR = new(Bytes32)
	i += copy(fb.Header.PrevKeyMR[:], data[i:i+len(fb.Header.PrevKeyMR)])
	fb.Header.PrevLedgerKeyMR = new(Bytes32)
	i += copy(fb.Header.PrevLedgerKeyMR[:], data[i:i+len(fb.Header.PrevLedgerKeyMR)])
	fb.Header.ExchangeRate = binary.BigEndian.Uint64(data[i : i+8])
	i += 8
	fb.Header.Height = binary.BigEndian.Uint32(data[i : i+4])
	i += 4

	expansionsize, read := binary.Varint(data[i:])
	fb.Header.ExpansionSize = expansionsize
	i += read
	fb.Header.ExpansionBytes = make([]byte, expansionsize)
	copy(fb.Header.ExpansionBytes, data[i:i+int(expansionsize)])
	i += int(expansionsize) // TODO: This should be safe, as the expansion size is never > max int

	fb.Header.TransactionCount = binary.BigEndian.Uint32(data[i : i+4])
	i += 4
	fb.Header.BodySize = binary.BigEndian.Uint32(data[i : i+4])
	i += 4

	// TODO: Body
	fb.Transactions = make([]*FactoidTransaction, fb.Header.TransactionCount)
	period := 0
	for c := range fb.Transactions {
		// Before each fct tx, we need to see if there is a marker byte that indicates a minute marker
		for data[i] == FBlockMinuteMarker {
			if period > len(fb.endOfPeriod) {
				return fmt.Errorf("too many minute markers")
			}
			fb.endOfPeriod[period] = c
			period++ // The next period encountered will be the next minute
			i += 1
		}

		fb.Transactions[c] = new(FactoidTransaction)
		read, err := fb.Transactions[c].Decode(data[i:])
		if err != nil {
			return err
		}
		i += read
	}

	// If we have not hit the end of our periods, a single byte will remain
	for period < len(fb.endOfPeriod) {
		fb.endOfPeriod[period] = int(fb.Header.TransactionCount)
		period++ // The next period encountered will be the next minute
		i += 1
	}

	// Set out computed fields
	keyMr, err := fb.ComputeKeyMR()
	if err != nil {
		return err
	}
	ledgerMr, err := fb.ComputeLedgerKeyMR()
	if err != nil {
		return err
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

	data := make([]byte, len(header)+int(fb.Header.BodySize))

	i := 0
	i += copy(data[i:], header)

	period := 0
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

	expansionSize := varintf.Encode(uint64(fb.Header.ExpansionSize))
	data := make([]byte, FBlockMinHeaderLen+len(expansionSize)+len(fb.Header.ExpansionBytes))
	i := 0
	i += copy(data[i:], factoidBlockChainID[:])
	i += copy(data[i:], fb.Header.BodyMR[:])
	i += copy(data[i:], fb.Header.PrevKeyMR[:])
	i += copy(data[i:], fb.Header.PrevLedgerKeyMR[:])

	binary.BigEndian.PutUint64(data[i:], fb.Header.ExchangeRate)
	i += 8
	binary.BigEndian.PutUint32(data[i:], fb.Header.Height)
	i += 4
	i += copy(data[i:], expansionSize)
	// Currently all expansion bytes are stored in the ExpansionBytes. So just write them out
	i += copy(data[i:], fb.Header.ExpansionBytes)
	binary.BigEndian.PutUint32(data[i:], fb.Header.TransactionCount)
	i += 4
	binary.BigEndian.PutUint32(data[i:], fb.Header.BodySize)
	i += 4

	return data, nil
}

// ComputeLedgerKeyMR computes the keymr of the factoid block including transaction
// signatures.
func (fb FBlock) ComputeKeyMR() (Bytes32, error) {
	return fb.computeKeyMR(false)
}

// ComputeLedgerKeyMR computes the keymr of the factoid block excluding transaction
// signatures.
func (fb FBlock) ComputeLedgerKeyMR() (Bytes32, error) {
	return fb.computeKeyMR(true)
}

func (fb FBlock) computeKeyMR(ledger bool) (Bytes32, error) {
	if !fb.IsPopulated() {
		return Bytes32{}, fmt.Errorf("not populated")
	}

	leaves := make([][]byte, 2)
	header, err := fb.MarshalBinaryHeader()
	if err != nil {
		return Bytes32{}, err
	}

	var body [32]byte
	if ledger {
		body, err = fb.ComputeLedgerBodyMR()
	} else {
		body, err = fb.ComputeBodyMR()
	}
	if err != nil {
		return Bytes32{}, err
	}

	headerHash := sha256.Sum256(header)
	if ledger { // Merkle leaves are flipped for the ledger keymr
		leaves[0] = body[:]
		leaves[1] = headerHash[:]
	} else {
		leaves[0] = headerHash[:]
		leaves[1] = body[:]
	}

	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DoubleOddNodes: true, DisableHashLeaves: true})
	if err := tree.Generate(leaves, sha256.New()); err != nil {
		return Bytes32{}, err
	}
	root := tree.Root()
	var keyMR Bytes32
	copy(keyMR[:], root.Hash)
	return keyMR, nil
}

// ComputeBodyMR computes the merkle root of the transactions in the body including
// their signatures
func (fb FBlock) ComputeBodyMR() (Bytes32, error) {
	return fb.computeBodyMR(false)
}

// ComputeBodyMR computes the merkle root of the transactions in the body excluding
// their signatures
func (fb FBlock) ComputeLedgerBodyMR() (Bytes32, error) {
	return fb.computeBodyMR(true)
}

// computeBodyMR will calculate the merkle root of all the transactions in the body.
// If `ledger` is true, signature blocks of the transactions are excluded.
func (fb FBlock) computeBodyMR(ledger bool) (Bytes32, error) {
	if !fb.IsPopulated() {
		return Bytes32{}, fmt.Errorf("not populated")
	}

	// Transactions + minute markers are included
	leaves := make([][]byte, len(fb.Transactions)+len(fb.endOfPeriod))
	period := 0
	c := 0
	for i, trans := range fb.Transactions {
		for period < len(fb.endOfPeriod) && i != 0 && i == fb.endOfPeriod[period] {
			period++
			leaves[c] = []byte{FBlockMinuteMarker}
			c++
		}

		var data []byte
		var err error
		if ledger { // Ledger does not marshal signature fields
			data, err = trans.MarshalLedgerBinary()
		} else {
			data, err = trans.MarshalBinary()
		}
		if err != nil {
			return Bytes32{}, err
		}
		leaves[c] = data
		c++
	}

	for period < len(fb.endOfPeriod) {
		period++
		leaves[c] = []byte{FBlockMinuteMarker}
		c++
	}

	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DoubleOddNodes: true})
	if err := tree.Generate(leaves, sha256.New()); err != nil {
		return Bytes32{}, err
	}
	root := tree.Root()
	var bodyMR Bytes32
	copy(bodyMR[:], root.Hash)
	return bodyMR, nil
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

// Transaction efficiently finds and returns the *FactoidTransaction in fb.Transactions
// for the given txid, if it exists. Otherwise, Transaction returns nil.
func (fb FBlock) Transaction(txid Bytes32) *FactoidTransaction {
	ei := sort.Search(len(fb.Transactions), func(i int) bool {
		return bytes.Compare(fb.Transactions[i].TransactionID[:], fb.Transactions[i].TransactionID[:]) >= 0
	})
	if ei < len(fb.Transactions) && *fb.Transactions[ei].TransactionID == txid {
		return fb.Transactions[ei]
	}
	return nil
}
