package merkletree

import (
	"bytes"
	"fmt"
	"hash"
	"testing"

	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
)

func recNodeRoot(roots [][]byte, h hash.Hash) []byte {
	if len(roots) == 1 {
		return roots[0]
	}

	left := recNodeRoot(roots[:len(roots)/2], h)
	right := recNodeRoot(roots[len(roots)/2:], h)
	h.Reset()
	h.Write(nodeHashPrefix)
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func hex(b []byte) string { return fmt.Sprintf("%x", b) }

func TestStack(t *testing.T) {
	blake, _ := blake2b.New256(nil)
	s := NewStack(blake)

	// test some known roots
	if s.Root() != nil {
		t.Error("wrong Stack root for empty stack")
	}

	roots := make([][]byte, 32)
	for i := range roots {
		roots[i] = make([]byte, 32)
		s.AppendNode(roots[i])
	}
	if hex(s.Root()) != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong Stack root for 32 empty roots")
	}

	s.Reset()
	roots[0][0] = 1
	for _, root := range roots {
		s.AppendNode(root)
	}
	if hex(s.Root()) != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong Stack root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		s.Reset()
		for j := range roots {
			fastrand.Read(roots[j][:])
			s.AppendNode(roots[j])
		}
		if !bytes.Equal(s.Root(), recNodeRoot(roots, blake)) {
			t.Error("Stack root does not match reference implementation")
		}
	}

	// test an odd number of roots
	s.Reset()
	roots = roots[:5]
	for _, root := range roots {
		s.AppendNode(root)
	}
	refRoot := recNodeRoot([][]byte{recNodeRoot(roots[:4], blake), roots[4]}, blake)
	if !bytes.Equal(s.Root(), refRoot) {
		t.Error("Stack root does not match reference implementation")
	}

	// test NumRoots
	if s.NumNodes() != 5 {
		t.Error("wrong number of nodes reported:", s.NumNodes())
	}
}

func BenchmarkStack1TB(b *testing.B) {
	const sectorsPerTerabyte = 262144
	node := make([]byte, 32)
	blake, _ := blake2b.New256(nil)
	b.ReportAllocs()
	s := NewStack(blake)
	for i := 0; i < b.N; i++ {
		s.Reset()
		for j := 0; j < sectorsPerTerabyte; j++ {
			s.AppendNode(node)
		}
	}
}
