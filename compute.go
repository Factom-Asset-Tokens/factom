package factom

import (
	"crypto/sha256"
	"crypto/sha512"

	merkle "github.com/AdamSLevy/go-merkle"
)

// ComputeDBlockHeaderHash returns sha256(data[:DBlockHeaderLen]).
func ComputeDBlockHeaderHash(data []byte) Bytes32 {
	return sha256.Sum256(data[:DBlockHeaderLen])
}

// ComputeEBlockHeaderHash returns sha256(data[:EBlockHeaderLen]).
func ComputeEBlockHeaderHash(data []byte) Bytes32 {
	return sha256.Sum256(data[:EBlockHeaderLen])
}

// ComputeDBlockBodyMR returns the merkle root of the tree created with
// elements as leaves, where the leaves are hashed.
func ComputeDBlockBodyMR(elements [][]byte) (Bytes32, error) {
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DoubleOddNodes: true})
	if err := tree.Generate(elements, sha256.New()); err != nil {
		return Bytes32{}, err
	}
	root := tree.Root()
	var bodyMR Bytes32
	copy(bodyMR[:], root.Hash)
	return bodyMR, nil
}

// ComputeEBlockBodyMR returns the merkle root of the tree created with
// elements as leaves, where the leaves are not hashed.
func ComputeEBlockBodyMR(elements [][]byte) (Bytes32, error) {
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{
		DoubleOddNodes:    true,
		DisableHashLeaves: true})
	if err := tree.Generate(elements, sha256.New()); err != nil {
		return Bytes32{}, err
	}
	root := tree.Root()
	var bodyMR Bytes32
	copy(bodyMR[:], root.Hash)
	return bodyMR, nil
}

// ComputeFullHash returns sha256(data).
func ComputeFullHash(data []byte) Bytes32 {
	return sha256.Sum256(data)
}

// ComputeKeyMR returns sha256(headerHash|bodyMR).
func ComputeKeyMR(headerHash, bodyMR *Bytes32) Bytes32 {
	data := make([]byte, len(headerHash)+len(bodyMR))
	i := copy(data, headerHash[:])
	copy(data[i:], bodyMR[:])
	return sha256.Sum256(data)
}

// ChainID returns the chain ID for a set of NameIDs.
func ChainID(nameIDs []Bytes) Bytes32 {
	hash := sha256.New()
	for _, id := range nameIDs {
		idSum := sha256.Sum256(id)
		hash.Write(idSum[:])
	}
	c := hash.Sum(nil)
	var chainID Bytes32
	copy(chainID[:], c)
	return chainID
}

// ComputeEntryHash returns the Entry hash of data. Entry's are hashed via:
// sha256(sha512(data) + data).
func ComputeEntryHash(data []byte) Bytes32 {
	sum := sha512.Sum512(data)
	saltedSum := make([]byte, len(sum)+len(data))
	i := copy(saltedSum, sum[:])
	copy(saltedSum[i:], data)
	return sha256.Sum256(saltedSum)
}
