package merkletree

import "hash"

type TreeHasher interface {
	HashLeaf(leaf []byte) []byte
	// HashChildren computes interior nodes.
	HashChildren(l, r []byte) []byte
}

var _ TreeHasher = DefaultTreeHasher{}

type DefaultTreeHasher struct {
	h hash.Hash
}

func (d DefaultTreeHasher) HashLeaf(leaf []byte) []byte {
	return sum(d.h, leafHashPrefix, leaf)
}

func (d DefaultTreeHasher) HashChildren(l, r []byte) []byte {
	return sum(d.h, nodeHashPrefix, l, r)
}
