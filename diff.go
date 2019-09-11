package merkletree

import (
	"bytes"
	"hash"
	"io"
	"math/bits"
)

// BuildDiffProof constructs a Merkle diff for the specified leaf ranges, using
// the provided SubtreeHasher. The ranges must be sorted and non-overlapping.
func BuildDiffProof(ranges []LeafRange, h SubtreeHasher, numLeaves uint64) (proof [][]byte, err error) {
	// This code is a direct copy of the BuildMultiRangeProof code, except that
	// it ends by consuming until numLeaves instead of math.MaxUint64. This can
	// result in a larger proof, but the extra proof hashes are required for
	// certain diffs.
	if !validRangeSet(ranges) {
		panic("BuildDiffProof: illegal set of proof ranges")
	}
	var leafIndex uint64
	consumeUntil := func(end uint64) error {
		for leafIndex != end {
			subtreeSize := nextSubtreeSize(leafIndex, end)
			root, err := h.NextSubtreeRoot(subtreeSize)
			if err != nil {
				return err
			}
			proof = append(proof, root)
			leafIndex += uint64(subtreeSize)
		}
		return nil
	}
	for _, r := range ranges {
		if err := consumeUntil(r.Start); err != nil {
			return nil, err
		}
		if err := h.Skip(int(r.End - r.Start)); err != nil {
			return nil, err
		}
		leafIndex += r.End - r.Start
	}
	err = consumeUntil(numLeaves)
	if err == io.EOF {
		err = nil
	}
	return proof, err
}

// VerifyDiffProof verifies a proof produced by BuildDiffProof using leaf hashes
// produced by lh, which must contain the concatenation of the leaf hashes
// within the proof ranges.
func VerifyDiffProof(sh SubtreeHasher, numLeaves uint64, h hash.Hash, ranges []LeafRange, proof [][]byte, root []byte) (bool, error) {
	// This code is a direct copy of the VerifyMultiRangeProof code, except that
	// it ends by consuming until numLeaves instead of math.MaxUint64.
	// Surprisingly, this change doesn't appear to be necessary; however, for
	// safety, it's best to be explicit.
	if !validRangeSet(ranges) {
		panic("VerifyDiffProof: illegal set of proof ranges")
	}
	tree := New(h)
	var leafIndex uint64
	consumeUntil := func(end uint64) error {
		for leafIndex != end && len(proof) > 0 {
			subtreeSize := nextSubtreeSize(leafIndex, end)
			i := bits.TrailingZeros64(uint64(subtreeSize))
			if err := tree.PushSubTree(i, proof[0]); err != nil {
				return err
			}
			proof = proof[1:]
			leafIndex += uint64(subtreeSize)
		}
		return nil
	}
	for _, r := range ranges {
		if err := consumeUntil(r.Start); err != nil {
			return false, err
		}
		for leafIndex != r.End {
			subtreeSize := nextSubtreeSize(leafIndex, r.End)
			root, err := sh.NextSubtreeRoot(subtreeSize)
			if err != nil {
				return false, err
			}
			i := bits.TrailingZeros64(uint64(subtreeSize))
			if err := tree.PushSubTree(i, root); err != nil {
				panic(err)
			}
			leafIndex += uint64(subtreeSize)
		}
	}
	err := consumeUntil(numLeaves)
	return bytes.Equal(tree.Root(), root), err
}
