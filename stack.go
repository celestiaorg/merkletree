package merkletree

import (
	"hash"
	"math/bits"
)

// A Stack is a Merkle tree that stores at most one node per level. If a node
// is inserted at a level already containing a node, the nodes are merged into
// the next level. This process repeats until it reaches an open level.
//
// For example, after five leaf hashes have been inserted, the stack only
// retains two nodes: one node created from the first leaf hashes, and one
// node containing the last. After seven nodes have been inserted, the stack
// retains three nodes: one for the first four leaf hashes, one for the next
// two, and the last one.
//
// Stacks are an alternative to storing the full Merkle tree; they
// compress the tree to O(log2(n)) space at the cost of reduced functionality
// (nodes can only be appended to the "end" of the stack; arbitrary insertion
// is not possible).
type Stack struct {
	stack [][]byte
	used  uint64 // one bit per stack elem; also number of nodes
	h     hash.Hash
	buf   []byte
}

func (s *Stack) leafHash(leaf []byte) []byte {
	s.h.Reset()
	s.h.Write(leafHashPrefix)
	s.h.Write(leaf)
	return s.h.Sum(s.buf[:0])
}

func (s *Stack) nodeHash(left, right []byte) []byte {
	s.h.Reset()
	s.h.Write(nodeHashPrefix)
	s.h.Write(left)
	s.h.Write(right)
	return s.h.Sum(s.buf[:0])
}

func (s *Stack) appendNodeAtHeight(node []byte, height uint64) {
	if height >= 64 {
		panic("appendNodeAtHeight: height must be < 64")
	}
	// seek to first open slot, merging nodes as we go
	i := height
	for ; s.used&(1<<i) != 0; i++ {
		node = s.nodeHash(s.stack[i], node)
	}
	// ensure stack is large enough
	if i >= uint64(len(s.stack)) {
		s.stack = append(s.stack, make([][]byte, 1+i-uint64(len(s.stack)))...)
		s.stack = s.stack[:cap(s.stack)] // append may have extended cap
	}
	s.stack[i] = append(s.stack[i][:0], node...)
	s.used += 1 << height // nice
}

// AppendNode appends node to the right side of the Merkle tree.
func (s *Stack) AppendNode(node []byte) {
	s.appendNodeAtHeight(node, 0)
}

// NumNodes returns the number of nodes appended to the stack since the last
// call to Reset.
func (s *Stack) NumNodes() int {
	return int(s.used)
}

// Reset clears the stack.
func (s *Stack) Reset() {
	s.used = 0 // nice
}

// Root returns the root of the Merkle tree. It does not modify the stack. If
// the stack is empty, Root returns nil.
func (s *Stack) Root() []byte {
	i := uint64(bits.TrailingZeros64(s.used))
	if i == 64 {
		return nil
	}
	root := s.stack[i]
	for i++; i < 64; i++ {
		if s.used&(1<<i) != 0 {
			root = s.nodeHash(s.stack[i], root)
		}
	}
	// avoiding leaking internal memory
	return append([]byte(nil), root...)
}

// NewStack returns a Stack using the specified hash function.
func NewStack(h hash.Hash) *Stack {
	return &Stack{
		h:   h,
		buf: make([]byte, h.Size()),
	}
}
