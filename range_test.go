package merkletree

import (
	"bytes"
	"hash"
	"reflect"
	"testing"

	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
)

func Root(b []byte, h hash.Hash, leafSize int) []byte {
	root, _ := ReaderRoot(bytes.NewReader(b), h, leafSize)
	return root
}

// A precalcSubtreeHasher wraps an underlying SubtreeHasher. It uses
// precalculated subtree roots where possible, only falling back to the
// underlying SubtreeHasher if needed.
type precalcSubtreeHasher struct {
	precalc     [][]byte
	subtreeSize int
	s           *Stack
	sh          SubtreeHasher
}

func (p *precalcSubtreeHasher) NextSubtreeRoot(n int) []byte {
	if n%p.subtreeSize == 0 && len(p.precalc) >= n/p.subtreeSize {
		np := n / p.subtreeSize
		p.s.Reset()
		for _, root := range p.precalc[:np] {
			p.s.AppendNode(root)
		}
		p.precalc = p.precalc[np:]
		p.sh.Skip(n)
		return p.s.Root()
	}
	return p.sh.NextSubtreeRoot(n)
}

func (p *precalcSubtreeHasher) Skip(n int) {
	skippedHashes := n / p.subtreeSize
	if n%p.subtreeSize != 0 {
		skippedHashes++
	}
	p.precalc = p.precalc[skippedHashes:]
	p.sh.Skip(n)
}

func newPrecalcSubtreeHasher(precalc [][]byte, subtreeSize int, h hash.Hash, sh SubtreeHasher) *precalcSubtreeHasher {
	return &precalcSubtreeHasher{
		precalc:     precalc,
		subtreeSize: subtreeSize,
		s:           NewStack(h),
		sh:          sh,
	}
}

func TestBuildVerifyRangeProof(t *testing.T) {
	// test some known proofs
	blake, _ := blake2b.New256(nil)
	leafData := make([]byte, 1<<22)
	const leafSize = 64
	numLeaves := len(leafData) / 64
	// convenience functions
	s := NewStack(blake)
	leafHash, nodeHash := s.leafHash, s.nodeHash

	proof := BuildRangeProof(0, numLeaves, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
	if len(proof) != 0 {
		t.Error("BuildRangeProof constructed an incorrect proof for the entire sector")
	}

	proof = BuildRangeProof(0, 1, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
	root := leafHash(leafData[:leafSize])
	for i := range proof {
		root = nodeHash(root, proof[i])
	}
	if hex(root) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for the first leaf")
	} else if !VerifyRangeProof(leafData[:leafSize], blake, leafSize, 0, 1, proof, root) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	proof = BuildRangeProof(numLeaves-1, numLeaves, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
	root = leafHash(leafData[len(leafData)-leafSize:])
	for i := range proof {
		root = nodeHash(proof[len(proof)-i-1], root)
	}
	if hex(root) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for the last leaf")
	} else if !VerifyRangeProof(leafData[len(leafData)-leafSize:], blake, leafSize, numLeaves-1, numLeaves, proof, root) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	proof = BuildRangeProof(10, 11, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
	root = leafHash(leafData[10*leafSize:][:leafSize])
	root = nodeHash(root, proof[2])
	root = nodeHash(proof[1], root)
	root = nodeHash(root, proof[3])
	root = nodeHash(proof[0], root)
	for i := 4; i < len(proof); i++ {
		root = nodeHash(root, proof[i])
	}
	if hex(root) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for a middle leaf")
	} else if !VerifyRangeProof(leafData[10*leafSize:11*leafSize], blake, leafSize, 10, 11, proof, root) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	// this is the largest possible proof
	midl, midr := numLeaves/2-1, numLeaves/2+1
	proof = BuildRangeProof(midl, midr, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
	left := leafHash(leafData[midl*leafSize:][:leafSize])
	for i := 0; i < len(proof)/2; i++ {
		left = nodeHash(proof[len(proof)/2-i-1], left)
	}
	right := leafHash(leafData[(midr-1)*leafSize:][:leafSize])
	for i := len(proof) / 2; i < len(proof); i++ {
		right = nodeHash(right, proof[i])
	}
	root = nodeHash(left, right)
	if hex(root) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for worst-case inputs")
	} else if !VerifyRangeProof(leafData[midl*leafSize:midr*leafSize], blake, leafSize, midl, midr, proof, root) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	// test some random proofs against VerifyRangeProof
	for i := 0; i < 5; i++ {
		start := fastrand.Intn(numLeaves - 1)
		end := start + fastrand.Intn(numLeaves-start)
		proof := BuildRangeProof(start, end, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
		if !VerifyRangeProof(leafData[start*leafSize:end*leafSize], blake, leafSize, start, end, proof, root) {
			t.Errorf("BuildRangeProof constructed an incorrect proof for range %v-%v", start, end)
		}
	}

	// test a proof with precomputed inputs
	precalcRoots := [][]byte{
		Root(leafData[:len(leafData)/2], blake, leafSize),
		Root(leafData[len(leafData)/2:], blake, leafSize),
	}
	precalc := newPrecalcSubtreeHasher(precalcRoots, numLeaves/2, blake, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
	proof = BuildRangeProof(numLeaves-1, numLeaves, precalc)
	recalcProof := BuildRangeProof(numLeaves-1, numLeaves, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
	if !reflect.DeepEqual(proof, recalcProof) {
		t.Fatal("precalc failed")
	}

	// test malformed inputs
	if VerifyRangeProof(make([]byte, leafSize), blake, leafSize, 0, 1, nil, nil) {
		t.Error("VerifyRangeProof verified an incorrect proof")
	}
}

func TestBuildVerifyReaderRangeProof(t *testing.T) {
	blake, _ := blake2b.New256(nil)
	for i := 0; i < 10; i++ {
	retry:
		leafSize := fastrand.Intn(1 << 8)
		data := fastrand.Bytes(leafSize*4 + fastrand.Intn(1<<10))
		numLeaves := len(data) / leafSize
		if len(data)%leafSize != 0 {
			numLeaves++
		}
		start := fastrand.Intn(numLeaves - 1)
		end := start + fastrand.Intn(numLeaves-start)
		if start == end {
			goto retry
		}
		proof, err := BuildReaderRangeProof(bytes.NewReader(data), blake, leafSize, start, end)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := VerifyReaderRangeProof(bytes.NewReader(data[start*leafSize:]), blake, leafSize, start, end, proof, Root(data, blake, leafSize))
		if err != nil {
			t.Fatal(err)
		} else if !ok {
			t.Fatal("VerifyReaderProof failed to verify proof produced by BuildReaderProof")
		}
	}
}

func BenchmarkBuildRangeProof(b *testing.B) {
	blake, _ := blake2b.New256(nil)
	leafData := fastrand.Bytes(1 << 22)
	const leafSize = 64
	numLeaves := len(leafData) / 64

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = BuildRangeProof(start, end, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, numLeaves/2))
	b.Run("mid", benchRange(numLeaves/2, 1+numLeaves/2))
	b.Run("full", benchRange(0, numLeaves-1))
}

func BenchmarkBuildRangeProofPrecalc(b *testing.B) {
	blake, _ := blake2b.New256(nil)
	leafData := fastrand.Bytes(1 << 22)
	const leafSize = 64
	numLeaves := len(leafData) / 64
	root := Root(leafData, blake, leafSize)

	// precalculate nodes to depth 4
	precalcRoots := make([][]byte, 16)
	precalcSize := numLeaves / 16
	for i := range precalcRoots {
		precalcRoots[i] = Root(leafData[i*precalcSize*leafSize:][:precalcSize*leafSize], blake, leafSize)
	}

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			precalc := newPrecalcSubtreeHasher(precalcRoots, precalcSize, blake, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
			b.ReportAllocs()
			proof := BuildRangeProof(start, end, precalc)
			if !VerifyRangeProof(leafData[start*leafSize:end*leafSize], blake, leafSize, start, end, proof, root) {
				b.Fatal("precalculated roots are incorrect")
			}
			for i := 0; i < b.N; i++ {
				precalc = newPrecalcSubtreeHasher(precalcRoots, precalcSize, blake, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
				_ = BuildRangeProof(start, end, precalc)
			}
		}
	}

	b.Run("single", benchRange(numLeaves-1, numLeaves))
	b.Run("sixteenth", benchRange(numLeaves-numLeaves/16, numLeaves))
}

func BenchmarkVerifyRangeProof(b *testing.B) {
	blake, _ := blake2b.New256(nil)
	leafData := fastrand.Bytes(1 << 22)
	const leafSize = 64
	numLeaves := len(leafData) / 64
	root := Root(leafData, blake, leafSize)

	benchRange := func(start, end int) func(*testing.B) {
		proof := BuildRangeProof(start, end, NewSubtreeReader(bytes.NewReader(leafData), leafSize, blake))
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = VerifyRangeProof(leafData[start*leafSize:end*leafSize], blake, leafSize, start, end, proof, root)
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, numLeaves/2))
	b.Run("mid", benchRange(numLeaves/2, 1+numLeaves/2))
	b.Run("full", benchRange(0, numLeaves-1))
}
