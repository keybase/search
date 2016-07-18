package index

import (
	"github.com/jxguan/go-datastructures/bitarray"

	"hash"
)

// SecureIndex defines the elements in a secure index.
type SecureIndex struct {
	BloomFilter bitarray.BitArray // The blinded bloom filter, which is the main part of the index.
	DocID       int               // The document ID that this index is for.
	Size        uint64            // The number of buckets in the bloom filter.
	Hash        func() hash.Hash  // The hash function to be used for HMAC.
}
