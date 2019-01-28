package merkletree

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"reflect"
	"testing"

	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
)

// bytesRoot is a helper function that calculates the Merkle root of b.
func bytesRoot(b []byte, h hash.Hash, leafSize int) []byte {
	root, err := ReaderRoot(bytes.NewReader(b), h, leafSize)
	if err != nil {
		// should be unreachable, since ReaderRoot only reports unexpected
		// errors returned by the supplied io.Reader, and bytes.Reader does
		// not return any such errors.
		panic(err)
	}
	return root
}

// A precalcSubtreeHasher wraps an underlying SubtreeHasher. It uses
// precalculated subtree roots where possible, only falling back to the
// underlying SubtreeHasher if needed.
type precalcSubtreeHasher struct {
	precalc     [][]byte
	subtreeSize int
	h           hash.Hash
	sh          SubtreeHasher
}

func (p *precalcSubtreeHasher) NextSubtreeRoot(n int) ([]byte, error) {
	if n%p.subtreeSize == 0 && len(p.precalc) >= n/p.subtreeSize {
		np := n / p.subtreeSize
		tree := New(p.h)
		for _, root := range p.precalc[:np] {
			tree.PushSubTree(0, root)
		}
		p.precalc = p.precalc[np:]
		return tree.Root(), p.sh.Skip(n)
	}
	return p.sh.NextSubtreeRoot(n)
}

func (p *precalcSubtreeHasher) Skip(n int) error {
	skippedHashes := n / p.subtreeSize
	if n%p.subtreeSize != 0 {
		skippedHashes++
	}
	p.precalc = p.precalc[skippedHashes:]
	return p.sh.Skip(n)
}

func newPrecalcSubtreeHasher(precalc [][]byte, subtreeSize int, h hash.Hash, sh SubtreeHasher) *precalcSubtreeHasher {
	return &precalcSubtreeHasher{
		precalc:     precalc,
		subtreeSize: subtreeSize,
		h:           h,
		sh:          sh,
	}
}

// TestNextSubtreeSize tests the nextSubtreeSize helper function.
func TestNextSubtreeSize(t *testing.T) {
	tests := []struct {
		start, end uint64
		size       int
	}{
		{0, 1, 1},
		{0, 2, 2},
		{0, 3, 2},
		{0, 100, 64},

		{1, 2, 1},
		{1, 3, 1},
		{1, 4, 1},
		{1, 100, 1},

		{2, 3, 1},
		{2, 4, 2},
		{2, 5, 2},
		{2, 100, 2},

		{3, 4, 1},
		{3, 5, 1},
		{3, 6, 1},
		{3, 100, 1},

		{4, 5, 1},
		{4, 6, 2},
		{4, 7, 2},
		{4, 8, 4},
		{4, 100, 4},

		{6, 7, 1},
		{6, 8, 2},
		{6, 9, 2},
		{6, 100, 2},

		{8, 9, 1},
		{8, 10, 2},
		{8, 12, 4},
		{8, 15, 4},
		{8, 16, 8},
		{8, 100, 8},
	}
	for _, test := range tests {
		if size := nextSubtreeSize(test.start, test.end); size != test.size {
			t.Errorf("expected %v,%v -> %v; got %v", test.start, test.end, test.size, size)
		}
	}
}

// A mockSubtreeHasher records the calls made to it while returning nil hashes.
type mockSubtreeHasher struct {
	leaves int
	pos    int
	calls  []string
}

func (msh *mockSubtreeHasher) NextSubtreeRoot(subtreeSize int) ([]byte, error) {
	msh.calls = append(msh.calls, fmt.Sprintf("Keep [%v,%v)", msh.pos, msh.pos+subtreeSize))
	if msh.pos >= msh.leaves {
		return nil, io.EOF
	}
	msh.pos += subtreeSize
	return nil, nil
}

func (msh *mockSubtreeHasher) Skip(n int) error {
	msh.calls = append(msh.calls, fmt.Sprintf("Skip [%v,%v)", msh.pos, msh.pos+n))
	msh.pos += n
	if msh.pos > msh.leaves {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// TestBuildMultiRangeProof uses a mock SubtreeHasher to test whether
// BuildMultiRange proof is examining the correct ranges of the tree.
func TestBuildMultiRangeProof(t *testing.T) {
	tests := []struct {
		leaves int
		ranges []LeafRange
		calls  []string
	}{

		//       ┌──┴───*
		//    *──┴──┐   │
		//  ┌─┴─┐ *─┴─┐ │
		//  0   1 2   3 4
		//            ^
		{
			leaves: 5,
			ranges: []LeafRange{{3, 4}},
			calls: []string{
				"Keep [0,2)",
				"Keep [2,3)",
				"Skip [3,4)",
				"Keep [4,8)",
				"Keep [8,16)", // overshoot -- algorithm terminates here
			},
		},

		//       ┌──┴───*
		//    *──┴──┐   │
		//  ┌─┴─┐ ┌─┴─* │
		//  0   1 2   3 4
		//        ^
		{
			leaves: 5,
			ranges: []LeafRange{{2, 3}},
			calls: []string{
				"Keep [0,2)",
				"Skip [2,3)",
				"Keep [3,4)",
				"Keep [4,8)",
				"Keep [8,16)",
			},
		},

		//       ┌──┴───┐
		//    ┌──┴──*   │
		//  ┌─┴─* ┌─┴─┐ │
		//  0   1 2   3 4
		//  ^           ^
		{
			leaves: 5,
			ranges: []LeafRange{{0, 1}, {4, 5}},
			calls: []string{
				"Skip [0,1)",
				"Keep [1,2)",
				"Keep [2,4)",
				"Skip [4,5)",
				"Keep [5,6)",
			},
		},

		//               ┌────────┴────────┐
		//         ┌─────┴─────┐           │
		//      *──┴──┐     ┌──┴──┐     ┌──┴──┐
		//    ┌─┴─┐ *─┴─┐ ┌─┴─* *─┴─┐ ┌─┴─┐ ┌─┴─*
		//    0   1 2   3 4   5 6   7 8   9 10  11
		//              ^^^         ^^^^^^^^^
		{
			leaves: 12,
			ranges: []LeafRange{{3, 5}, {7, 11}},
			calls: []string{
				"Keep [0,2)",
				"Keep [2,3)",
				"Skip [3,5)",
				"Keep [5,6)",
				"Keep [6,7)",
				"Skip [7,11)",
				"Keep [11,12)",
				"Keep [12,16)",
			},
		},

		//               ┌────────┴────────*
		//         ┌─────┴─────*           │
		//      ┌──┴──┐     ┌──┴──┐     ┌──┴──┐
		//    ┌─┴─┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐
		//    0   1 2   3 4   5 6   7 8   9 10  11
		//    ^^^^^ ^   ^
		{
			leaves: 12,
			ranges: []LeafRange{{0, 2}, {2, 3}, {3, 4}},
			calls: []string{
				"Skip [0,2)",
				"Skip [2,3)",
				"Skip [3,4)",
				"Keep [4,8)",
				"Keep [8,16)",
				"Keep [16,32)",
			},
		},
	}
	for _, test := range tests {
		m := &mockSubtreeHasher{leaves: test.leaves}
		if _, err := BuildMultiRangeProof(test.ranges, m); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(m.calls, test.calls) {
			t.Errorf("BuildMultiRangeProof made incorrect calls to SubtreeHasher:\nExpected:\n\t%v\nGot:\n\t%v", test.calls, m.calls)
		}
	}
}

// TestBuildVerifyMultiRangeProof tests the BuildMultiRangeProof and
// VerifyMultiRangeProof functions.
func TestBuildVerifyMultiRangeProof(t *testing.T) {
	// setup proof parameters
	const dataSize = 1 << 22
	const leafSize = 64
	const numLeaves = dataSize / leafSize
	blake, _ := blake2b.New256(nil)
	leafData := make([]byte, 1<<22)
	leafHashes := make([][]byte, numLeaves)
	for i := range leafHashes {
		leafHashes[i] = leafSum(blake, leafData[i*leafSize:][:leafSize])
	}
	root := bytesRoot(leafData, blake, leafSize)

	// convenience functions
	nodeHash := func(left, right []byte) []byte {
		return nodeSum(blake, left, right)
	}
	buildProof := func(ranges []LeafRange) [][]byte {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var sh SubtreeHasher
		if fastrand.Intn(2) == 0 {
			sh = NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake)
		} else {
			sh = NewCachedSubtreeHasher(leafHashes, blake)
		}
		proof, err := BuildMultiRangeProof(ranges, sh)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	verifyProof := func(ranges []LeafRange, proof [][]byte) bool {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var lh LeafHasher
		if fastrand.Intn(2) == 0 {
			var rs []io.Reader
			for _, r := range ranges {
				rs = append(rs, bytes.NewReader(leafData[r.Start*leafSize:r.End*leafSize]))
			}
			lh = NewReaderLeafHasher(io.MultiReader(rs...), blake, leafSize)
		} else {
			var hashes [][]byte
			for _, r := range ranges {
				hashes = append(hashes, leafHashes[r.Start:r.End]...)
			}
			lh = NewCachedLeafHasher(hashes)
		}
		ok, err := VerifyMultiRangeProof(lh, blake, ranges, proof, root)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// test some known proofs
	proofRange := []LeafRange{
		{0, 1},
		{1, 2},
		{2, numLeaves},
	}
	proof := buildProof(proofRange)
	if len(proof) != 0 {
		t.Error("BuildRangeProof constructed an incorrect proof for the entire sector")
	}

	proofRange = []LeafRange{
		{0, 1},
		{numLeaves - 1, numLeaves},
	}
	proof = buildProof(proofRange)
	leftSide := leafHashes[0]
	rightSide := leafHashes[numLeaves-1]
	for i := range proof[:len(proof)/2] {
		leftSide = nodeHash(leftSide, proof[i])
		rightSide = nodeHash(proof[len(proof)-i-1], rightSide)
	}
	checkRoot := nodeHash(leftSide, rightSide)
	if hex.EncodeToString(checkRoot) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for the first leaf")
	} else if !verifyProof(proofRange, proof) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	proofRange = []LeafRange{
		{0, 1},
		{numLeaves / 2, numLeaves/2 + 1},
	}
	proof = buildProof(proofRange)
	leftSide = leafHashes[0]
	for _, h := range proof[:len(proof)/2] {
		leftSide = nodeHash(leftSide, h)
	}
	rightSide = leafHashes[numLeaves/2]
	for _, h := range proof[:len(proof)/2] {
		rightSide = nodeHash(rightSide, h)
	}
	checkRoot = nodeHash(leftSide, rightSide)
	if hex.EncodeToString(checkRoot) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for the first leaf")
	} else if !verifyProof(proofRange, proof) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	// this is the largest possible proof
	proofRange = nil
	for i := uint64(0); i < numLeaves; i += 2 {
		proofRange = append(proofRange, LeafRange{i, i + 1})
	}
	proof = buildProof(proofRange)
	for i := range proof {
		if !bytes.Equal(proof[i], leafHashes[2*i]) {
			t.Error("BuildRangeProof constructed an incorrect proof for worst-case inputs")
			break
		}
	}
	if !verifyProof(proofRange, proof) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	// for more intensive testing, use smaller trees
	buildSmallProof := func(ranges []LeafRange, nLeaves int) [][]byte {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var sh SubtreeHasher
		if fastrand.Intn(2) == 0 {
			sh = NewReaderSubtreeHasher(bytes.NewReader(leafData[:leafSize*nLeaves]), leafSize, blake)
		} else {
			sh = NewCachedSubtreeHasher(leafHashes[:nLeaves], blake)
		}
		proof, err := BuildMultiRangeProof(ranges, sh)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	verifySmallProof := func(ranges []LeafRange, proof [][]byte, nLeaves int) bool {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var lh LeafHasher
		if fastrand.Intn(2) == 0 {
			var rs []io.Reader
			for _, r := range ranges {
				rs = append(rs, bytes.NewReader(leafData[r.Start*leafSize:r.End*leafSize]))
			}
			lh = NewReaderLeafHasher(io.MultiReader(rs...), blake, leafSize)
		} else {
			var hashes [][]byte
			for _, r := range ranges {
				hashes = append(hashes, leafHashes[r.Start:r.End]...)
			}
			lh = NewCachedLeafHasher(hashes)
		}
		smallRoot := bytesRoot(leafData[:leafSize*nLeaves], blake, leafSize)
		ok, err := VerifyMultiRangeProof(lh, blake, ranges, proof, smallRoot)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// build and verify all 4180 possible proofs for a 9-leaf tree.
	var allRangeSets func(min, max uint64) [][]LeafRange
	allRangeSets = func(min, max uint64) [][]LeafRange {
		var all [][]LeafRange
		for i := min; i < max; i++ {
			for j := i + 1; j <= max; j++ {
				all = append(all, []LeafRange{{i, j}})
				for _, sub := range allRangeSets(j, max) {
					withPrefix := append([]LeafRange{{i, j}}, sub...)
					all = append(all, withPrefix)
				}
			}
		}
		return all
	}
	for _, rs := range allRangeSets(0, 9) {
		proof := buildSmallProof(rs, 9)
		if !verifySmallProof(rs, proof, 9) {
			t.Errorf("BuildMultiRangeProof constructed an incorrect proof for ranges %v", rs)
		}
	}
}

// TestBuildVerifyRangeProof tests the BuildRangeProof and VerifyRangeProof
// functions.
func TestBuildVerifyRangeProof(t *testing.T) {
	// setup proof parameters
	blake, _ := blake2b.New256(nil)
	leafData := make([]byte, 1<<22)
	const leafSize = 64
	numLeaves := len(leafData) / 64
	leafHashes := make([][]byte, numLeaves)
	for i := range leafHashes {
		leafHashes[i] = leafSum(blake, leafData[i*leafSize:][:leafSize])
	}
	root := bytesRoot(leafData, blake, leafSize)

	// convenience functions
	leafHash := func(leaf []byte) []byte {
		return leafSum(blake, leaf)
	}
	nodeHash := func(left, right []byte) []byte {
		return nodeSum(blake, left, right)
	}
	buildProof := func(start, end int) [][]byte {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var sh SubtreeHasher
		if fastrand.Intn(2) == 0 {
			sh = NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake)
		} else {
			sh = NewCachedSubtreeHasher(leafHashes, blake)
		}
		proof, err := BuildRangeProof(start, end, sh)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	verifyProof := func(start, end int, proof [][]byte) bool {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var lh LeafHasher
		if fastrand.Intn(2) == 0 {
			lh = NewReaderLeafHasher(bytes.NewReader(leafData[start*leafSize:end*leafSize]), blake, leafSize)
		} else {
			lh = NewCachedLeafHasher(leafHashes[start:end])
		}
		ok, err := VerifyRangeProof(lh, blake, start, end, proof, root)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// test some known proofs
	proof := buildProof(0, numLeaves)
	if len(proof) != 0 {
		t.Error("BuildRangeProof constructed an incorrect proof for the entire sector")
	}

	proof = buildProof(0, 1)
	checkRoot := leafHash(leafData[:leafSize])
	for i := range proof {
		checkRoot = nodeHash(checkRoot, proof[i])
	}
	if hex.EncodeToString(checkRoot) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for the first leaf")
	} else if !verifyProof(0, 1, proof) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	proof = buildProof(numLeaves-1, numLeaves)
	checkRoot = leafHash(leafData[len(leafData)-leafSize:])
	for i := range proof {
		checkRoot = nodeHash(proof[len(proof)-i-1], checkRoot)
	}
	if hex.EncodeToString(checkRoot) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for the last leaf")
	} else if !verifyProof(numLeaves-1, numLeaves, proof) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	proof = buildProof(10, 11)
	checkRoot = leafHash(leafData[10*leafSize:][:leafSize])
	checkRoot = nodeHash(checkRoot, proof[2])
	checkRoot = nodeHash(proof[1], checkRoot)
	checkRoot = nodeHash(checkRoot, proof[3])
	checkRoot = nodeHash(proof[0], checkRoot)
	for i := 4; i < len(proof); i++ {
		checkRoot = nodeHash(checkRoot, proof[i])
	}
	if hex.EncodeToString(checkRoot) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for a middle leaf")
	} else if !verifyProof(10, 11, proof) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	// this is the largest possible proof
	midl, midr := numLeaves/2-1, numLeaves/2+1
	proof = buildProof(midl, midr)
	left := leafHash(leafData[midl*leafSize:][:leafSize])
	for i := 0; i < len(proof)/2; i++ {
		left = nodeHash(proof[len(proof)/2-i-1], left)
	}
	right := leafHash(leafData[(midr-1)*leafSize:][:leafSize])
	for i := len(proof) / 2; i < len(proof); i++ {
		right = nodeHash(right, proof[i])
	}
	checkRoot = nodeHash(left, right)
	if hex.EncodeToString(checkRoot) != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("BuildRangeProof constructed an incorrect proof for worst-case inputs")
	} else if !verifyProof(midl, midr, proof) {
		t.Error("VerifyRangeProof failed to verify a known correct proof")
	}

	// for more intensive testing, use smaller trees
	buildSmallProof := func(start, end, nLeaves int) [][]byte {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var sh SubtreeHasher
		if fastrand.Intn(2) == 0 {
			sh = NewReaderSubtreeHasher(bytes.NewReader(leafData[:leafSize*nLeaves]), leafSize, blake)
		} else {
			sh = NewCachedSubtreeHasher(leafHashes[:nLeaves], blake)
		}
		proof, err := BuildRangeProof(start, end, sh)
		if err != nil {
			t.Fatal(err)
		}
		return proof

	}
	verifySmallProof := func(start, end int, proof [][]byte, nLeaves int) bool {
		// flip a coin to decide whether to use leaf data or leaf hashes
		var lh LeafHasher
		if fastrand.Intn(2) == 0 {
			lh = NewReaderLeafHasher(bytes.NewReader(leafData[start*leafSize:end*leafSize]), blake, leafSize)
		} else {
			lh = NewCachedLeafHasher(leafHashes[start:end])
		}
		smallRoot := bytesRoot(leafData[:leafSize*nLeaves], blake, leafSize)
		ok, err := VerifyRangeProof(lh, blake, start, end, proof, smallRoot)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// test some random proofs against VerifyRangeProof
	for nLeaves := 1; nLeaves <= 65; nLeaves++ {
		for n := 0; n < 5; n++ {
			start := fastrand.Intn(nLeaves)
			end := start + fastrand.Intn(nLeaves-start) + 1
			proof := buildSmallProof(start, end, nLeaves)
			if !verifySmallProof(start, end, proof, nLeaves) {
				t.Errorf("BuildRangeProof constructed an incorrect proof for nLeaves=%v, range %v-%v", nLeaves, start, end)
			}

			// corrupt the proof; it should fail to verify
			if len(proof) == 0 {
				continue
			}
			switch fastrand.Intn(3) {
			case 0:
				// modify an element of the proof
				proof[fastrand.Intn(len(proof))][fastrand.Intn(blake.Size())] += 1
			case 1:
				// add an element to the proof
				proof = append(proof, make([]byte, blake.Size()))
				i := fastrand.Intn(len(proof))
				proof[i], proof[len(proof)-1] = proof[len(proof)-1], proof[i]
			case 2:
				// delete a random element of the proof
				i := fastrand.Intn(len(proof))
				proof = append(proof[:i], proof[i+1:]...)
			}
			if verifyProof(start, end, proof) {
				t.Errorf("VerifyRangeProof verified an incorrect proof for nLeaves=%v, range %v-%v", nLeaves, start, end)
			}
		}
	}

	// build and verify every possible proof for a small tree
	for start := 0; start < 12; start++ {
		for end := start + 1; end <= 12; end++ {
			proof := buildSmallProof(start, end, 12)
			if !verifySmallProof(start, end, proof, 12) {
				t.Errorf("BuildRangeProof constructed an incorrect proof for range %v-%v", start, end)
			}
		}
	}

	// manually verify every hash in a proof
	//
	// NOTE: this is the same proof described in the BuildRangeProof comment:
	//
	//               ┌────────┴────────*
	//         ┌─────┴─────┐           │
	//      *──┴──┐     ┌──┴──*     ┌──┴──┐
	//    ┌─┴─┐ *─┴─┐ ┌─┴─* ┌─┴─┐ ┌─┴─┐ ┌─┴─┐
	//    0   1 2   3 4   5 6   7 8   9 10  11
	//              ^^^
	//
	proof = buildSmallProof(3, 5, 12)
	subtreeRoot := func(i, j int) []byte {
		return bytesRoot(leafData[i*leafSize:j*leafSize], blake, leafSize)
	}
	manualProof := [][]byte{
		subtreeRoot(0, 2),
		subtreeRoot(2, 3),
		subtreeRoot(5, 6),
		subtreeRoot(6, 8),
		subtreeRoot(8, 12),
	}
	if !reflect.DeepEqual(proof, manualProof) {
		t.Error("BuildRangeProof constructed a proof that differs from manual proof")
	}

	// test a proof with precomputed inputs
	precalcRoots := [][]byte{
		bytesRoot(leafData[:len(leafData)/2], blake, leafSize),
		bytesRoot(leafData[len(leafData)/2:], blake, leafSize),
	}
	precalc := newPrecalcSubtreeHasher(precalcRoots, numLeaves/2, blake, NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake))
	proof, err := BuildRangeProof(numLeaves-1, numLeaves, precalc)
	if err != nil {
		t.Fatal(err)
	}
	recalcProof, err := BuildRangeProof(numLeaves-1, numLeaves, NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake))
	if !reflect.DeepEqual(proof, recalcProof) {
		t.Fatal("precalc failed")
	}
}

// TestBuildProofRangeEOF tests that BuildRangeProof behaves correctly in the
// presence of EOF errors.
func TestBuildProofRangeEOF(t *testing.T) {
	// setup proof parameters
	blake, _ := blake2b.New256(nil)
	leafData := make([]byte, 1<<22)
	const leafSize = 64
	numLeaves := len(leafData) / 64
	leafHashes := make([][]byte, numLeaves)
	for i := range leafHashes {
		leafHashes[i] = leafSum(blake, leafData[i*leafSize:][:leafSize])
	}

	// build a proof for the middle of the tree, but only supply half of the
	// leafData. This should trigger an io.ErrUnexpectedEOF when
	// BuildRangeProof tries to skip over the proof range.
	midl, midr := numLeaves/2-1, numLeaves/2+1

	// test with both ReaderSubtreeHasher and CachedSubtreeHasher
	shs := []SubtreeHasher{
		NewReaderSubtreeHasher(bytes.NewReader(leafData[:len(leafData)/2]), leafSize, blake),
		NewCachedSubtreeHasher(leafHashes[:len(leafHashes)/2], blake),
	}
	for _, sh := range shs {
		if _, err := BuildRangeProof(midl, midr, sh); err != io.ErrUnexpectedEOF {
			t.Fatal("expected io.ErrUnexpectedEOF, got", err)
		}
	}
}

// TestProofConversion tests that "old" single-leaf Merkle proofs can be
// converted into "new" single-leaf Merkle range proofs, and vice versa.
func TestProofConversion(t *testing.T) {
	blake, _ := blake2b.New256(nil)

	tests := []struct {
		leafSize  int
		numLeaves int
	}{
		{leafSize: 64, numLeaves: 8},
		{leafSize: 64, numLeaves: 11},
		{leafSize: 64, numLeaves: 31},
		{leafSize: 64, numLeaves: 129},
		{leafSize: 89, numLeaves: 8},
		{leafSize: 74, numLeaves: 11},
		{leafSize: 5, numLeaves: 31},
		{leafSize: 100, numLeaves: 129},
	}
	for _, test := range tests {
		leafData := fastrand.Bytes(test.leafSize * test.numLeaves)

		buildOldProof := func(proofIndex int) [][]byte {
			t := New(blake)
			t.SetIndex(uint64(proofIndex))
			buf := bytes.NewBuffer(leafData)
			for buf.Len() > 0 {
				t.Push(buf.Next(test.leafSize))
			}
			_, proof, _, _ := t.Prove()
			return proof[1:]
		}

		buildNewProof := func(proofIndex int) [][]byte {
			sh := NewReaderSubtreeHasher(bytes.NewReader(leafData), test.leafSize, blake)
			proof, err := BuildRangeProof(proofIndex, proofIndex+1, sh)
			if err != nil {
				t.Fatal(err)
			}
			return proof
		}

		for proofIndex := 0; proofIndex < test.numLeaves; proofIndex++ {
			oldproof := buildOldProof(proofIndex)
			newproof := buildNewProof(proofIndex)
			if !reflect.DeepEqual(ConvertSingleProofToRangeProof(oldproof, proofIndex), newproof) {
				t.Fatalf("Failed to convert old->new for index %v", proofIndex)
			}
			if !reflect.DeepEqual(ConvertRangeProofToSingleProof(newproof, proofIndex), oldproof) {
				t.Errorf("Failed to convert new->old for index %v", proofIndex)
			}
		}
	}

	// test invalid/untrusted inputs to ensure that they do not panic
	proof := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		proof = proof[:1+fastrand.Intn(1000)]
		proofIndex := fastrand.Intn(len(proof))
		if fastrand.Intn(4) == 0 {
			// 25% of the time, use a ridiculous proof index
			proofIndex = len(proof) + fastrand.Intn(1000)
		}
		ConvertRangeProofToSingleProof(proof, proofIndex)
		ConvertRangeProofToSingleProof(proof, proofIndex)
	}
}

// TestProofOfModification uses multi-range proofs to prove arbitrary
// modifications to a Merkle tree.
func TestProofOfModification(t *testing.T) {
	const leafSize = 64
	const numLeaves = 12
	const dataSize = leafSize * numLeaves
	blake, _ := blake2b.New256(nil)
	leafData := fastrand.Bytes(dataSize)
	leafHashes := make([][]byte, numLeaves)
	for i := range leafHashes {
		leafHashes[i] = leafSum(blake, leafData[i*leafSize:][:leafSize])
	}
	root := bytesRoot(leafData, blake, leafSize)

	// The modifications we want to make are:
	//
	// - Swap(6,11)
	// - Trim(6)
	// - Swap(7, 10)
	// - Append(12)
	// - Append(13)
	//
	// Using these appended hashes:
	newLeafHash12 := fastrand.Bytes(32)
	newLeafHash13 := fastrand.Bytes(32)

	// We begin by constructing a multi-range proof for the old tree, covering
	// any affected leaves.
	ranges := []LeafRange{
		{6, 7},
		{7, 8},
		{10, 11},
		{11, 12},
	}
	proof, err := BuildMultiRangeProof(ranges, NewCachedSubtreeHasher(leafHashes, blake))
	if err != nil {
		t.Fatal(err)
	}
	// We complete the proof by appending the leaves inside the ranges:
	proof = append(proof, leafHashes[6], leafHashes[7], leafHashes[10], leafHashes[11])

	// Then we apply the modifications and construct the new root:
	leafHashes[6], leafHashes[11] = leafHashes[11], leafHashes[6] // Swap(6, 11)
	leafHashes = leafHashes[:len(leafHashes)-1]                   // Trim(6)
	leafHashes[7], leafHashes[10] = leafHashes[10], leafHashes[7] // Swap(7, 10)
	leafHashes = append(leafHashes, newLeafHash12)                // Append(12)
	leafHashes = append(leafHashes, newLeafHash13)                // Append(13)
	newRoot, err := NewCachedSubtreeHasher(leafHashes, blake).NextSubtreeRoot(len(leafHashes))
	if err != nil {
		t.Fatal(err)
	}

	// The proof and the new root are sent to the verifier. The verifier also
	// knows newLeafHash12 and newLeafHash13.

	// To verify the proof, we first split the proof into subtree hashes and leaf hashes:
	var numRangeHashes int
	for _, r := range ranges {
		numRangeHashes += int(r.End - r.Start)
	}
	proofHashes, rangeHashes := proof[:len(proof)-numRangeHashes], proof[len(proof)-numRangeHashes:]
	ok, err := VerifyMultiRangeProof(NewCachedLeafHasher(rangeHashes), blake, ranges, proofHashes, root)
	if err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("failed to verify old root")
	}

	// Next, we apply the modifications to our hashes and verify the new root:
	rangeHashes[0], rangeHashes[3] = rangeHashes[3], rangeHashes[0] // Swap(6, 11)
	rangeHashes = rangeHashes[:len(rangeHashes)-1]                  // Trim(6)
	rangeHashes[1], rangeHashes[2] = rangeHashes[2], rangeHashes[1] // Swap(7, 10)
	rangeHashes = append(rangeHashes, newLeafHash12)                // Append(12)
	rangeHashes = append(rangeHashes, newLeafHash13)                // Append(13)
	ranges = append(ranges, LeafRange{12, 13})                      // to include appended data
	ok, err = VerifyMultiRangeProof(NewCachedLeafHasher(rangeHashes), blake, ranges, proofHashes, newRoot)
	if err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("failed to verify new root")
	}
}

// BenchmarkBuildRangeProof benchmarks the performance of BuildRangeProof for
// various proof ranges.
func BenchmarkBuildRangeProof(b *testing.B) {
	blake, _ := blake2b.New256(nil)
	leafData := fastrand.Bytes(1 << 22)
	const leafSize = 64
	numLeaves := len(leafData) / 64

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = BuildRangeProof(start, end, NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake))
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, numLeaves/2))
	b.Run("mid", benchRange(numLeaves/2, 1+numLeaves/2))
	b.Run("full", benchRange(0, numLeaves-1))
}

// BenchmarkBuildRangeProof benchmarks the performance of BuildRangeProof for
// various proof ranges when a subset of the roots have been precalculated.
func BenchmarkBuildRangeProofPrecalc(b *testing.B) {
	blake, _ := blake2b.New256(nil)
	leafData := fastrand.Bytes(1 << 22)
	const leafSize = 64
	numLeaves := len(leafData) / 64
	root := bytesRoot(leafData, blake, leafSize)

	verifyProof := func(start, end int, proof [][]byte) bool {
		lh := NewReaderLeafHasher(bytes.NewReader(leafData[start*leafSize:end*leafSize]), blake, leafSize)
		ok, err := VerifyRangeProof(lh, blake, start, end, proof, root)
		if err != nil {
			b.Fatal(err)
		}
		return ok
	}

	// precalculate nodes to depth 4
	precalcRoots := make([][]byte, 16)
	precalcSize := numLeaves / 16
	for i := range precalcRoots {
		precalcRoots[i] = bytesRoot(leafData[i*precalcSize*leafSize:][:precalcSize*leafSize], blake, leafSize)
	}

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			precalc := newPrecalcSubtreeHasher(precalcRoots, precalcSize, blake, NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake))
			b.ReportAllocs()
			proof, _ := BuildRangeProof(start, end, precalc)
			if !verifyProof(start, end, proof) {
				b.Fatal("precalculated roots are incorrect")
			}
			for i := 0; i < b.N; i++ {
				precalc = newPrecalcSubtreeHasher(precalcRoots, precalcSize, blake, NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake))
				_, _ = BuildRangeProof(start, end, precalc)
			}
		}
	}

	b.Run("single", benchRange(numLeaves-1, numLeaves))
	b.Run("sixteenth", benchRange(numLeaves-numLeaves/16, numLeaves))
}

// BenchmarkVerifyRange benchmarks the performance of VerifyRangeProof
// for various proof ranges.
func BenchmarkVerifyRangeProof(b *testing.B) {
	blake, _ := blake2b.New256(nil)
	leafData := fastrand.Bytes(1 << 22)
	const leafSize = 64
	numLeaves := len(leafData) / 64
	root := bytesRoot(leafData, blake, leafSize)

	verifyProof := func(start, end int, proof [][]byte) bool {
		lh := NewReaderLeafHasher(bytes.NewReader(leafData[start*leafSize:end*leafSize]), blake, leafSize)
		ok, err := VerifyRangeProof(lh, blake, start, end, proof, root)
		if err != nil {
			b.Fatal(err)
		}
		return ok
	}

	benchRange := func(start, end int) func(*testing.B) {
		proof, _ := BuildRangeProof(start, end, NewReaderSubtreeHasher(bytes.NewReader(leafData), leafSize, blake))
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = verifyProof(start, end, proof)
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, numLeaves/2))
	b.Run("mid", benchRange(numLeaves/2, 1+numLeaves/2))
	b.Run("full", benchRange(0, numLeaves-1))
}
