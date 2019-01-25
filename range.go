package merkletree

import (
	"bytes"
	"hash"
	"io"
	"io/ioutil"
	"math/bits"
)

// A LeafRange represents the contiguous set of leaves [Start,End).
type LeafRange struct {
	Start uint64
	End   uint64
}

// nextSubtreeSize returns the size of the subtree adjacent to start that does
// not overlap end.
func nextSubtreeSize(start, end uint64) int {
	ideal := bits.TrailingZeros64(start)
	max := 63 - bits.LeadingZeros64(end-start)
	if ideal > max {
		return 1 << uint(max)
	}
	return 1 << uint(ideal)
}

// validRangeSet checks whether a set of ranges is sorted and non-overlapping.
func validRangeSet(ranges []LeafRange) bool {
	for i, r := range ranges {
		if r.Start < 0 || r.Start >= r.End {
			return false
		}
		if i > 0 && ranges[i-1].End > r.Start {
			return false
		}
	}
	return true
}

// A SubtreeHasher calculates subtree roots in sequential order, for use with
// BuildRangeProof.
type SubtreeHasher interface {
	// NextSubtreeRoot returns the root of the next n leaves. If fewer than n
	// leaves are left in the tree, NextSubtreeRoot returns the root of those
	// leaves and nil. If no leaves are left, NextSubtreeRoot returns io.EOF.
	NextSubtreeRoot(n int) ([]byte, error)
	// Skip skips the next n leaves. If fewer than n leaves are left in the
	// tree, Skip returns io.ErrUnexpectedEOF. If exactly n leaves are left,
	// Skip returns nil (not io.EOF).
	Skip(n int) error
}

// ReaderSubtreeHasher implements SubtreeHasher by reading leaf data from an
// underlying stream.
type ReaderSubtreeHasher struct {
	r    io.Reader
	h    hash.Hash
	leaf []byte
}

// NextSubtreeRoot implements SubtreeHasher.
func (rsh *ReaderSubtreeHasher) NextSubtreeRoot(subtreeSize int) ([]byte, error) {
	tree := New(rsh.h)
	for i := 0; i < subtreeSize; i++ {
		n, err := io.ReadFull(rsh.r, rsh.leaf)
		if n > 0 {
			tree.Push(rsh.leaf[:n])
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break // reading a partial leaf is normal at the end of the stream
		} else if err != nil {
			return nil, err
		}
	}
	root := tree.Root()
	if root == nil {
		// we didn't read anything; return EOF to signal that there are no
		// more subtrees to hash.
		return nil, io.EOF
	}
	return root, nil
}

// Skip implements SubtreeHasher.
func (rsh *ReaderSubtreeHasher) Skip(n int) (err error) {
	skipSize := int64(len(rsh.leaf) * n)
	skipped, err := io.CopyN(ioutil.Discard, rsh.r, skipSize)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		if skipped == skipSize {
			return nil
		}
		return io.ErrUnexpectedEOF
	}
	return err
}

// NewReaderSubtreeHasher returns a new ReaderSubtreeHasher that reads leaf data from r.
func NewReaderSubtreeHasher(r io.Reader, leafSize int, h hash.Hash) *ReaderSubtreeHasher {
	return &ReaderSubtreeHasher{
		r:    r,
		h:    h,
		leaf: make([]byte, leafSize),
	}
}

// CachedSubtreeHasher implements SubtreeHasher using a set of precomputed
// leaf hashes.
type CachedSubtreeHasher struct {
	leafHashes [][]byte
	h          hash.Hash
}

// NextSubtreeRoot implements SubtreeHasher.
func (csh *CachedSubtreeHasher) NextSubtreeRoot(subtreeSize int) ([]byte, error) {
	if len(csh.leafHashes) == 0 {
		return nil, io.EOF
	}
	tree := New(csh.h)
	for i := 0; i < subtreeSize && len(csh.leafHashes) > 0; i++ {
		if err := tree.PushSubTree(0, csh.leafHashes[0]); err != nil {
			return nil, err
		}
		csh.leafHashes = csh.leafHashes[1:]
	}
	return tree.Root(), nil
}

// Skip implements SubtreeHasher.
func (csh *CachedSubtreeHasher) Skip(n int) error {
	if n > len(csh.leafHashes) {
		return io.ErrUnexpectedEOF
	}
	csh.leafHashes = csh.leafHashes[n:]
	return nil
}

// NewCachedSubtreeHasher creates a CachedSubtreeHasher using the specified
// leaf hashes and hash function.
func NewCachedSubtreeHasher(leafHashes [][]byte, h hash.Hash) *CachedSubtreeHasher {
	return &CachedSubtreeHasher{
		leafHashes: leafHashes,
		h:          h,
	}
}

// BuildRangeProof constructs a proof for the specified leaf ranges, using the
// provided SubtreeHasher. The ranges must be sorted and non-overlapping.
func BuildMultiRangeProof(ranges []LeafRange, h SubtreeHasher) (proof [][]byte, err error) {
	if len(ranges) == 0 {
		return nil, nil
	}
	if !validRangeSet(ranges) {
		panic("BuildMultiRangeProof: illegal set of proof ranges")
	}

	var leafIndex uint64
	for _, r := range ranges {
		// add proof hashes from leaves [leafIndex, r.Start)
		for leafIndex != r.Start {
			// consume the largest subtree that does not overlap r.Start
			subtreeSize := nextSubtreeSize(leafIndex, r.Start)
			root, err := h.NextSubtreeRoot(subtreeSize)
			if err != nil {
				return nil, err
			}
			proof = append(proof, root)
			leafIndex += uint64(subtreeSize)
		}

		// skip leaves within proof range
		if err := h.Skip(int(r.End - r.Start)); err != nil {
			return nil, err
		}
		leafIndex += r.End - r.Start
	}

	// keep adding proof hashes until NextSubtreeRoot returns io.EOF.
	endMask := leafIndex - 1
	for i := 0; i < 64; i++ {
		subtreeSize := uint64(1) << uint64(i)
		if endMask&subtreeSize == 0 {
			root, err := h.NextSubtreeRoot(int(subtreeSize))
			if err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}
			proof = append(proof, root)
		}
	}

	return proof, nil
}

// BuildRangeProof constructs a proof for the leaf range [proofStart,
// proofEnd) using the provided SubtreeHasher.
func BuildRangeProof(proofStart, proofEnd int, h SubtreeHasher) (proof [][]byte, err error) {
	if proofStart < 0 || proofStart > proofEnd || proofStart == proofEnd {
		panic("BuildRangeProof: illegal proof range")
	}
	return BuildMultiRangeProof([]LeafRange{{uint64(proofStart), uint64(proofEnd)}}, h)
}

// A LeafHasher returns the leaves of a Merkle tree in sequential order. When
// no more leaves are available, NextLeafHash must return io.EOF.
type LeafHasher interface {
	NextLeafHash() ([]byte, error)
}

// ReaderLeafHasher implements the LeafHasher interface by reading leaf data
// from the underlying stream.
type ReaderLeafHasher struct {
	r    io.Reader
	h    hash.Hash
	leaf []byte
}

// NextLeafHash implements LeafHasher.
func (rlh *ReaderLeafHasher) NextLeafHash() ([]byte, error) {
	n, err := io.ReadFull(rlh.r, rlh.leaf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	} else if n == 0 {
		return nil, io.EOF
	}
	return leafSum(rlh.h, rlh.leaf[:n]), nil
}

// NewReaderLeafHasher creates a ReaderLeafHasher with the specified stream,
// hash, and leaf size.
func NewReaderLeafHasher(r io.Reader, h hash.Hash, leafSize int) *ReaderLeafHasher {
	return &ReaderLeafHasher{
		r:    r,
		h:    h,
		leaf: make([]byte, leafSize),
	}
}

// CachedLeafHasher implements the LeafHasher interface by returning
// precomputed leaf hashes.
type CachedLeafHasher struct {
	leafHashes [][]byte
}

// NextLeafHash implements LeafHasher.
func (clh *CachedLeafHasher) NextLeafHash() ([]byte, error) {
	if len(clh.leafHashes) == 0 {
		return nil, io.EOF
	}
	h := clh.leafHashes[0]
	clh.leafHashes = clh.leafHashes[1:]
	return h, nil
}

// NewCachedLeafHasher creates a CachedLeafHasher from a set of precomputed
// leaf hashes.
func NewCachedLeafHasher(leafHashes [][]byte) *CachedLeafHasher {
	return &CachedLeafHasher{
		leafHashes: leafHashes,
	}
}

// VerifyMultiRangeProof verifies a proof produced by BuildMultiRangeProof
// using leaf hashes produced by lh, which must contain the concatenation of
// the leaf hashes within the proof ranges.
func VerifyMultiRangeProof(lh LeafHasher, h hash.Hash, ranges []LeafRange, proof [][]byte, root []byte) (bool, error) {
	if len(ranges) == 0 {
		return true, nil
	}
	if !validRangeSet(ranges) {
		panic("BuildMultiRangeProof: illegal set of proof ranges")
	}

	// manually build a tree using the proof hashes
	tree := New(h)

	var leafIndex uint64
	for _, r := range ranges {
		// add proof hashes from leaves [leafIndex, r.Start)
		for leafIndex != r.Start && len(proof) > 0 {
			// consume the largest subtree that does not overlap r.Start
			subtreeSize := nextSubtreeSize(leafIndex, r.Start)
			i := bits.TrailingZeros64(uint64(subtreeSize)) // log2
			if err := tree.PushSubTree(i, proof[0]); err != nil {
				// PushSubTree only returns an error if i is greater than the
				// current smallest subtree. Since the loop proceeds in
				// descending order, this should never happen.
				panic(err)
			}
			proof = proof[1:]
			leafIndex += uint64(subtreeSize)
		}

		// add leaf hashes within the proof range
		for i := r.Start; i < r.End; i++ {
			leafHash, err := lh.NextLeafHash()
			if err != nil {
				return false, err
			}
			if err := tree.PushSubTree(0, leafHash); err != nil {
				panic(err)
			}
		}
		leafIndex += r.End - r.Start
	}

	// add remaining proof hashes after the last range ends
	endMask := leafIndex - 1
	for i := 0; i < 64 && len(proof) > 0; i++ {
		subtreeSize := uint64(1) << uint64(i)
		if endMask&subtreeSize == 0 {
			if err := tree.PushSubTree(i, proof[0]); err != nil {
				// This *probably* should never happen, but just to guard
				// against adversarial inputs, return an error instead of
				// panicking.
				return false, err
			}
			proof = proof[1:]
			leafIndex += uint64(subtreeSize)
		}
	}

	return bytes.Equal(tree.Root(), root), nil
}

// VerifyRangeProof verifies a proof produced by BuildRangeProof using leaf
// hashes produced by lh, which must contain only the leaf hashes within the
// proof range.
func VerifyRangeProof(lh LeafHasher, h hash.Hash, proofStart, proofEnd int, proof [][]byte, root []byte) (bool, error) {
	if proofStart < 0 || proofStart > proofEnd || proofStart == proofEnd {
		panic("VerifyRangeProof: illegal proof range")
	}
	return VerifyMultiRangeProof(lh, h, []LeafRange{{uint64(proofStart), uint64(proofEnd)}}, proof, root)
}

// proofMapping returns an index-to-index mapping that maps a hash's index in
// a "new" proof (produced by BuildRangeProof) to its index in an "old" proof
// (produced by (*Tree).Prove), i.e. new[i] = old[m[i]].
func proofMapping(proofSize, proofIndex int) (mapping []int) {
	// For context, the problem we're solving is that (*Tree).Prove constructs
	// proofs in a different way than the newer range proofs for a single
	// leaf. The proof hashes themselves are the same, of course, but the
	// *order* in which they appear in the proof is different. For example, in
	// the tree below, the two orderings of a proof for index 3 are:
	//
	//                       ┌─────────┴───────*
	//                 *─────┴─────┐           │
	//              ┌──┴──┐     *──┴──┐     ┌──┴──┐
	// Index:       0     1     2     3     4     5
	// Old Proof:      1        0              2
	// New Proof:      0        1              2
	//
	// In other words, the old proofs proceed "bottom-up", tracing the path
	// from the proofIndex to the root of the tree, whereas the new proofs
	// proceed "left-to-right."
	//
	// There is a simple algorithm for converting old proofs to new proofs.
	// First, we iterate through the bits of the proofIndex; if the i'th bit
	// is a 0, we add to the "right-side" hashes; if it's a 1, we add it to
	// the "left-side". Then we just need to reverse the order of the left-
	// side hashes (see the comment in BuildRangeProof) and concatenate the
	// left side with the right side.
	//
	// Unfortunately, this algorithm only works for balanced trees (trees with
	// 2^n leaves). Consider a proof for index 4 in the above tree. The actual
	// proof should contain only two hashes, but the naive algorithm would
	// generate three -- one for each level. More specifically: the bits of 4
	// are 001, so the algorithm would see "right-side, right-side, left-
	// side." But after the first "right-side", there are no more leaves left
	// on the right side!
	//
	// So we have to augment the algorithm to be aware of these "missing
	// levels." Fortunately, we can exploit a property of unbalanced trees to
	// accomplish this without too much trouble. The property is: if a proof
	// is missing n hashes, they are always the hashes of the n largest right-
	// side subtrees. Or, stated another way: the proof will only include the
	// m *smallest* right-side subtrees. For example, we know that the proof
	// for index 4 contains only one right-side subtree hash; using the
	// property, we can be confident that the hash is of a single leaf.
	//
	// This lends itself to an easy change to the algorithm: simply stop
	// adding right-side hashes after we've hit the known limit. But how do we
	// know what the limit is? Easy: we know that there's a 1 bit in the
	// proofIndex for each left-side hash, so we just subtract the number of 1
	// bits from the total number of proof hashes.
	numRights := proofSize - bits.OnesCount(uint(proofIndex))
	var left, right []int
	for i := 0; len(left)+len(right) < proofSize; i++ {
		subtreeSize := 1 << uint64(i)
		if proofIndex&subtreeSize != 0 {
			// appending len(left)+len(right) is a little trick to ensure
			// that, whether we append to left or right, the combined sequence
			// is 0,1,2,3...
			left = append(left, len(left)+len(right))
		} else if len(right) < numRights {
			right = append(right, len(left)+len(right))
		}
	}
	// left-side needs to be reversed
	for i := range left {
		mapping = append(mapping, left[len(left)-i-1])
	}
	return append(mapping, right...)
}

// ConvertSingleProofToRangeProof converts a proof produced by (*Tree).Prove
// to a single-leaf range proof. proofIndex must be >= 0.
func ConvertSingleProofToRangeProof(proof [][]byte, proofIndex int) [][]byte {
	newproof := make([][]byte, len(proof))
	mapping := proofMapping(len(proof), proofIndex)
	for i, j := range mapping {
		newproof[i] = proof[j]
	}
	return newproof
}

// ConvertRangeProofToSingleProof converts a single-leaf range proof to the
// equivalent proof produced by (*Tree).Prove. proofIndex must be >= 0.
func ConvertRangeProofToSingleProof(proof [][]byte, proofIndex int) [][]byte {
	oldproof := make([][]byte, len(proof))
	mapping := proofMapping(len(proof), proofIndex)
	for i, j := range mapping {
		oldproof[j] = proof[i]
	}
	return oldproof
}
