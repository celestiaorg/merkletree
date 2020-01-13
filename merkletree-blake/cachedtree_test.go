package merkletree

import (
	"testing"

	"golang.org/x/crypto/blake2b"
)

// addSubTree will create a subtree of the desired height using the dataSeed to
// seed the data. addSubTree will add the data created in the subtree to the
// Tree as well. The tree must have the proveIndex set separately.
func addSubTree(height uint64, dataSeed []byte, subtreeProveIndex uint64, fullTree *Tree) (subTree *Tree) {
	data := blake2b.Sum256(dataSeed)
	leaves := 1 << height

	subTree = New()
	err := subTree.SetIndex(subtreeProveIndex)
	if err != nil {
		panic(err)
	}

	for i := 0; i < leaves; i++ {
		subTree.Push(data[:])
		fullTree.Push(data[:])
		data = blake2b.Sum256(data[:])
	}
	return subTree
}

// TestCachedTreeConstruction checks that a CachedTree will correctly build to
// the same merkle root as the Tree when using caches at various heights and
// lengths.
func TestCachedTreeConstruction(t *testing.T) {
	arbData := [][]byte{
		{1},
		{2},
		{3},
		{4},
		{5},
		{6},
		{7},
		{8},
	}

	// Test that a CachedTree with no elements will return the same value as a
	// tree with no elements.
	tree := New()
	cachedTree := NewCachedTree(0)
	if tree.Root() != cachedTree.Root() {
		t.Error("empty Tree and empty CachedTree do not match")
	}
	// Try comparing the root of a cached tree with one element, where the
	// cache height is 0.
	tree = New()
	cachedTree = NewCachedTree(0)
	tree.Push(arbData[0])
	cachedTree.PushSubTree(0, tree.Root())
	if tree.Root() != cachedTree.Root() {
		t.Error("naive 1-height Tree and CachedTree do not match")
	}

	// Try comparing the root of a cached tree where the cache height is 0, and
	// there are 3 cached elements.
	tree = New()
	subTree1 := New()
	subTree2 := New()
	cachedTree = NewCachedTree(0)
	// Create 3 subtrees, one for caching each element.
	subTree3 := New()
	subTree1.Push(arbData[0])
	subTree2.Push(arbData[1])
	subTree3.Push(arbData[2])
	// Pushed the cached roots into the cachedTree.
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree2.Root())
	cachedTree.PushSubTree(0, subTree3.Root())
	// Create a tree from the original elements.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	if tree.Root() != cachedTree.Root() {
		t.Error("adding 3 len cacheing is causing problems")
	}

	// Try comparing the root of a cached tree where the cache height is 1, and
	// there is 1 cached element.
	tree = New()
	subTree1 = New()
	cachedTree = NewCachedTree(1)
	// Build the subtrees to get the cached roots.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	// Supply the cached roots to the cached tree.
	cachedTree.PushSubTree(0, subTree1.Root())
	// Compare against a formally built tree.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	if cachedTree.Root() != tree.Root() {
		t.Error("comparison has failed")
	}

	// Mirror the above test, but attempt a mutation, which should cause a
	// failure.
	tree = New()
	subTree1 = New()
	cachedTree = NewCachedTree(1)
	// Build the subtrees to get the cached roots.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	// Supply the cached roots to the cached tree.
	cachedTree.PushSubTree(0, subTree1.Root())
	// Compare against a formally built tree.
	tree.Push(arbData[1]) // Intentional mistake.
	tree.Push(arbData[1])
	if cachedTree.Root() == tree.Root() {
		t.Error("comparison has succeeded despite mutation")
	}

	// Try comparing the root of a cached tree where the cache height is 2, and
	// there are 5 cached elements.
	tree = New()
	subTree1 = New()
	subTree2 = New()
	cachedTree = NewCachedTree(2)
	// Build the subtrees to get the cached roots.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree1.Push(arbData[2])
	subTree1.Push(arbData[3])
	subTree2.Push(arbData[4])
	subTree2.Push(arbData[5])
	subTree2.Push(arbData[6])
	subTree2.Push(arbData[7])
	// Supply the cached roots to the cached tree.
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree2.Root())
	// Compare against a formally built tree.
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			tree.Push(arbData[j])
		}
	}
	for i := 4; i < 8; i++ {
		tree.Push(arbData[i])
	}
	if cachedTree.Root() != tree.Root() {
		t.Error("comparison has failed")
	}

	// Try proving on an uninitialized cached tree.
	cachedTree = NewCachedTree(0)
	if err := cachedTree.SetIndex(0); err != nil {
		t.Fatal(err)
	}
	_, proofSet, _, _ := cachedTree.Prove(nil)
	if proofSet != nil {
		t.Error("proving an empty set resulted in a valid proof?")
	}
	cachedTree = NewCachedTree(1)
	if err := cachedTree.SetIndex(0); err != nil {
		t.Fatal(err)
	}
	_, proofSet, _, _ = cachedTree.Prove(nil)
	if proofSet != nil {
		t.Error("proving an empty set resulted in a valid proof?")
	}
	cachedTree = NewCachedTree(2)
	if err := cachedTree.SetIndex(0); err != nil {
		t.Fatal(err)
	}
	_, proofSet, _, _ = cachedTree.Prove(nil)
	if proofSet != nil {
		t.Error("proving an empty set resulted in a valid proof?")
	}

	// Try creating a cached proof with cache height 1, 2 cached nodes, index
	// 1.
	tree = New()
	subTree1 = New()
	err := subTree1.SetIndex(1) // subtree index 0-1, corresponding to index 1.
	if err != nil {
		t.Fatal(err)
	}
	subTree2 = New()
	cachedTree = NewCachedTree(1)
	err = cachedTree.SetIndex(1)
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree2.Push(arbData[2])
	subTree2.Push(arbData[3])
	// Supply the cached root to the cached tree.
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree2.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	tree.Push(arbData[3])
	root := tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ := subTree1.Prove()
	_, proofSet, proofIndex, numLeaves := cachedTree.Prove(subTreeProofSet)
	if !VerifyProof(root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was unsuccessful")
	}

	// Try creating a cached proof with cache height 0, 3 cached nodes, index
	// 2.
	tree = New()
	subTree1 = New()
	subTree2 = New()
	subTree3 = New()
	err = subTree3.SetIndex(0) // subtree index 2-0, corresponding to index 2.
	if err != nil {
		t.Fatal(err)
	}
	cachedTree = NewCachedTree(0)
	err = cachedTree.SetIndex(2)
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree2.Push(arbData[1])
	subTree3.Push(arbData[2])
	// Supply the cached root to the cached tree.
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree2.Root())
	cachedTree.PushSubTree(0, subTree3.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree3.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet)
	if !VerifyProof(root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was unsuccessful")
	}

	// Try creating a cached proof with cache height 2, 3 cached nodes, index
	// 6.
	tree = New()
	subTree1 = New()
	subTree2 = New()
	err = subTree2.SetIndex(2) // subtree index 1-2, corresponding to index 6.
	if err != nil {
		t.Fatal(err)
	}
	subTree3 = New()
	cachedTree = NewCachedTree(2)
	err = cachedTree.SetIndex(6)
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree1.Push(arbData[2])
	subTree1.Push(arbData[3])
	subTree2.Push(arbData[4])
	subTree2.Push(arbData[5])
	subTree2.Push(arbData[6])
	subTree2.Push(arbData[7])
	subTree3.Push(arbData[1])
	subTree3.Push(arbData[3])
	subTree3.Push(arbData[5])
	subTree3.Push(arbData[7])
	// Supply the cached root to the cached tree.
	cachedTree.PushSubTree(0, subTree1.Root())
	cachedTree.PushSubTree(0, subTree2.Root())
	cachedTree.PushSubTree(0, subTree3.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	tree.Push(arbData[3])
	tree.Push(arbData[4])
	tree.Push(arbData[5])
	tree.Push(arbData[6])
	tree.Push(arbData[7])
	tree.Push(arbData[1])
	tree.Push(arbData[3])
	tree.Push(arbData[5])
	tree.Push(arbData[7])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree2.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet)
	if !VerifyProof(root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was unsuccessful")
	}
}

// TestCachedTreeConstructionAuto uses automation to build out a wide set of
// trees of different types to make sure the Cached Tree maintains consistency
// with the actual tree.
func TestCachedTreeConstructionAuto(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	// Build out cached trees with up to 33 cached elements, each height 'h'.
	for h := uint64(0); h < 5; h++ {
		n := uint64(1) << h
		for i := uint64(0); i < 35; i++ {
			// Try creating a proof at each index.
			for j := uint64(0); j < i*n; j++ {
				tree := New()
				err := tree.SetIndex(j)
				if err != nil {
					t.Fatal(err)
				}
				cachedTree := NewCachedTree(h)
				err = cachedTree.SetIndex(j)
				if err != nil {
					t.Fatal(err)
				}
				var subProof [][32]byte

				// Build out 'i' subtrees that form the components of the cached
				// tree.
				for k := uint64(0); k < i; k++ {
					subtree := addSubTree(uint64(h), []byte{byte(k)}, j%n, tree)
					cachedTree.PushSubTree(0, subtree.Root())
					if tree.Root() != cachedTree.Root() {
						t.Error("naive 1-height Tree and Cached tree roots do not match")
					}

					// Get the proof of the subtree
					if k == j/n {
						_, subProof, _, _ = subtree.Prove()
					}
				}

				// Verify that the tree was built correctly.
				treeRoot, treeProof, treeProofIndex, treeLeaves := tree.Prove()
				if !VerifyProof(treeRoot, treeProof, treeProofIndex, treeLeaves) {
					t.Error("tree problems", i, j)
				}

				// Verify that the cached tree was built correctly.
				cachedRoot, cachedProof, cachedProofIndex, cachedLeaves := cachedTree.Prove(subProof)
				if !VerifyProof(cachedRoot, cachedProof, cachedProofIndex, cachedLeaves) {
					t.Error("cached tree problems", i, j)
				}
			}
		}
	}
}
