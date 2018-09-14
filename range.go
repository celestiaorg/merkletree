package merkletree

import (
	"bytes"
	"errors"
	"hash"
	"io"
	"io/ioutil"
)

// A SubtreeHasher calculates subtree roots in sequential order, for use with
// BuildRangeProof.
type SubtreeHasher interface {
	NextSubtreeRoot(n int) []byte
	Skip(n int)
}

// BuildRangeProof constructs a proof for the leaf range [start, end).
// subtreeRoot should return the root of the subtree comprising leaves [i,j),
// where j may extend beyond the size of the tree. subtreeRoot must return nil
// when i exceeds the size of the tree. subtreeRoot is guaranteed to be called
// with monotonically increasing i and j.
func BuildRangeProof(proofStart, proofEnd int, h SubtreeHasher) (proof [][]byte) {
	if proofStart < 0 || proofStart > proofEnd || proofStart == proofEnd {
		panic("BuildRangeProof: illegal proof range")
	}

	// add proof hashes from leaves [0, proofStart)
	leafIndex := 0
	for i := uint64(0); leafIndex < proofStart; i++ {
		subtreeSize := 1 << (64 - i)
		if proofStart&subtreeSize != 0 {
			root := h.NextSubtreeRoot(subtreeSize)
			if root == nil {
				break
			}
			proof = append(proof, root)
			leafIndex += subtreeSize
		}
	}

	// skip leaves within proof range
	h.Skip(proofEnd - proofStart)

	// add proof hashes from proofEnd onward, stopping when subtreeRoot
	// returns nil.
	endMask := 0 - uint64(proofEnd)
	for i := uint64(0); i < 64; i++ {
		subtreeSize := 1 << i
		if endMask&uint64(subtreeSize) != 0 {
			root := h.NextSubtreeRoot(subtreeSize)
			if root == nil {
				break
			}
			proof = append(proof, root)
			leafIndex += subtreeSize
		}
	}
	return proof
}

// VerifyRangeProof verifies a proof produced by BuildRangeProof.
func VerifyRangeProof(leafData []byte, h hash.Hash, leafSize, proofStart, proofEnd int, proof [][]byte, root []byte) bool {
	if proofStart < 0 || proofStart > proofEnd || proofStart == proofEnd {
		panic("VerifyRangeProof: illegal proof range")
	}
	ok, err := VerifyReaderRangeProof(bytes.NewReader(leafData), h, leafSize, proofStart, proofEnd, proof, root)
	return ok && err == nil
}

// A SubtreeReader reads leaf data from an underlying stream and uses it to
// calculate subtree roots.
type SubtreeReader struct {
	r    io.Reader
	leaf []byte
	s    *Stack
	err  error
}

// NextSubtreeRoot implements SubtreeHasher.
func (sr *SubtreeReader) NextSubtreeRoot(n int) []byte {
	if sr.err != nil {
		return nil
	}
	sr.s.Reset()
	for i := 0; i < n; i++ {
		n, err := io.ReadFull(sr.r, sr.leaf)
		if n > 0 {
			sr.s.AppendNode(sr.s.leafHash(sr.leaf[:n]))
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break // reading a partial leaf is normal at the end of the stream
		} else if err != nil {
			sr.err = err
			return nil
		}
	}
	return sr.s.Root()
}

// Skip implements SubtreeHasher.
func (sr *SubtreeReader) Skip(n int) {
	if sr.err != nil {
		return
	}
	skipSize := int64(len(sr.leaf) * n)
	if s, ok := sr.r.(io.Seeker); ok {
		_, sr.err = s.Seek(skipSize, io.SeekCurrent)
	} else {
		// fake a seek method
		_, sr.err = io.CopyN(ioutil.Discard, sr.r, skipSize)
	}
}

// Err returns the first error encountered by the underlying io.Reader. io.EOF
// and io.ErrUnexpectedEOF errors are suppressed.
func (sr *SubtreeReader) Err() error {
	return sr.err
}

// NewSubtreeReader returns a new SubtreeReader that reads leaf data from r.
func NewSubtreeReader(r io.Reader, leafSize int, h hash.Hash) *SubtreeReader {
	return &SubtreeReader{
		r:    r,
		leaf: make([]byte, leafSize),
		s:    NewStack(h),
	}
}

// BuildReaderRangeProof constructs a proof for the range [proofStart,
// proofEnd), using leaf data read from r.
func BuildReaderRangeProof(r io.Reader, h hash.Hash, leafSize, proofStart, proofEnd int) ([][]byte, error) {
	if proofStart < 0 || proofStart > proofEnd || proofStart == proofEnd {
		panic("BuildReaderRangeProof: illegal proof range")
	}
	sr := NewSubtreeReader(r, leafSize, h)
	proof := BuildRangeProof(proofStart, proofEnd, sr)
	return proof, sr.Err()
}

// VerifyReaderRangeProof verifies a proof produced by BuildRangeProof, using
// leaf data read from r, which must contain only the leaves within the proof
// range.
func VerifyReaderRangeProof(r io.Reader, h hash.Hash, leafSize, proofStart, proofEnd int, proof [][]byte, root []byte) (bool, error) {
	if proofStart < 0 || proofStart > proofEnd || proofStart == proofEnd {
		panic("VerifyReaderRangeProof: illegal proof range")
	}

	// manually build a stack using the proof hashes
	s := NewStack(h)

	// add proof hashes up to proofStart
	for i := uint64(63); i != ^uint64(0) && len(proof) > 0; i-- {
		subtreeSize := 1 << i
		if proofStart&subtreeSize != 0 {
			s.appendNodeAtHeight(proof[0], i)
			proof = proof[1:]
		}
	}

	// add leaf hashes
	leaf := make([]byte, leafSize)
	for i := proofStart; i < proofEnd; i++ {
		n, err := io.ReadFull(r, leaf)
		if n > 0 {
			s.AppendNode(s.leafHash(leaf[:n]))
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			if i == proofEnd-1 {
				break // last leaf was partial
			}
			return false, errors.New("insufficient leaf data in reader")
		} else if err != nil {
			return false, err
		}
	}

	// add proof hashes after proofEnd
	endMask := 0 - uint64(proofEnd)
	for i := uint64(0); len(proof) > 0; i++ {
		subtreeSize := 1 << i
		if endMask&uint64(subtreeSize) != 0 {
			s.appendNodeAtHeight(proof[0], i)
			proof = proof[1:]
		}
	}

	return bytes.Equal(s.Root(), root), nil
}
