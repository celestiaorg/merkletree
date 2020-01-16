package merkletree

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// TestReaderRoot calls ReaderRoot on a manually crafted dataset
// and checks the output.
func TestReaderRoot(t *testing.T) {
	mt := CreateMerkleTester(t)
	bytes8 := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	reader := bytes.NewReader(bytes8)
	root, err := ReaderRoot(reader, 1)
	if err != nil {
		t.Fatal(err)
	}
	if root != mt.roots[8] {
		t.Error("ReaderRoot returned the wrong root")
	}
}

// TestReaderRootPadding passes ReaderRoot a reader that has too few bytes to
// fill the last segment. The segment should not be padded out.
func TestReaderRootPadding(t *testing.T) {
	bytes1 := []byte{1}
	reader := bytes.NewReader(bytes1)
	root, err := ReaderRoot(reader, 2)
	if err != nil {
		t.Fatal(err)
	}

	expectedRoot := blake2b.Sum256([]byte{0, 1})
	if root != expectedRoot {
		t.Error("ReaderRoot returned the wrong root")
	}

	bytes3 := []byte{1, 2, 3}
	reader = bytes.NewReader(bytes3)
	root, err = ReaderRoot(reader, 2)
	if err != nil {
		t.Fatal(err)
	}

	baseLeft := blake2b.Sum256([]byte{0, 1, 2})
	baseRight := blake2b.Sum256([]byte{0, 3})
	expectedRoot = blake2b.Sum256(append(append([]byte{1}, baseLeft[:]...), baseRight[:]...))
	if root != expectedRoot {
		t.Error("ReaderRoot returned the wrong root")
	}
}

// TestBuildReaderProof calls BuildReaderProof on a manually crafted dataset
// and checks the output.
func TestBuildReaderProof(t *testing.T) {
	mt := CreateMerkleTester(t)
	bytes7 := []byte{0, 1, 2, 3, 4, 5, 6}
	reader := bytes.NewReader(bytes7)
	root, proofSet, numLeaves, err := BuildReaderProof(reader, 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if root != mt.roots[7] {
		t.Error("BuildReaderProof returned the wrong root")
	}
	if len(proofSet) != len(mt.proofSets[7][5]) {
		t.Fatal("BuildReaderProof returned a proof with the wrong length")
	}
	for i := range proofSet {
		if proofSet[i] != mt.proofSets[7][5][i] {
			t.Error("BuildReaderProof returned an incorrect proof")
		}
	}
	if numLeaves != 7 {
		t.Error("BuildReaderProof returned the wrong number of leaves")
	}
}

// TestBuildReaderProofPadding passes BuildReaderProof a reader that has too
// few bytes to fill the last segment. The segment should not be padded out.
func TestBuildReaderProofPadding(t *testing.T) {
	bytes1 := []byte{1}
	reader := bytes.NewReader(bytes1)
	root, proofSet, numLeaves, err := BuildReaderProof(reader, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	expectedRoot := LeafSum(bytes1)
	if root != expectedRoot {
		t.Error("ReaderRoot returned the wrong root")
	}
	if len(proofSet) != 1 {
		t.Fatal("proofSet is the incorrect length")
	}
	if proofSet[0] != expectedRoot {
		t.Error("proofSet is incorrect")
	}
	if numLeaves != 1 {
		t.Error("wrong number of leaves returned")
	}
}

// TestEmptyReader passes an empty reader into BuildReaderProof.
func TestEmptyReader(t *testing.T) {
	_, _, _, err := BuildReaderProof(new(bytes.Reader), 64, 5)
	if err == nil {
		t.Error(err)
	}
}
