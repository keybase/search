package index

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/jxguan/go-datastructures/bitarray"
)

// SecureIndex defines the elements in a secure index.
type SecureIndex struct {
	BloomFilter bitarray.BitArray // The blinded bloom filter, which is the main part of the index.
	DocID       int               // The document ID that this index is for.
	Size        uint64            // The number of buckets in the bloom filter.
	Hash        func() hash.Hash  // The hash function to be used for HMAC.
}

// Marshal serializes a SecureIndex into a byte slice.
// TODO: Use the `encoding.BinaryMarshaler` interface.
func (si *SecureIndex) Marshal() []byte {
	bfBytes, err := bitarray.Marshal(si.BloomFilter)
	if err != nil {
		fmt.Println("Cannot serialize the index to bytes")
	}
	length := 24 + len(bfBytes)
	result := make([]byte, length)
	binary.PutVarint(result, int64(si.DocID))
	binary.PutVarint(result[8:], int64(si.Hash().Size()))
	binary.PutUvarint(result[16:], si.Size)
	copy(result[24:], bfBytes)
	return result
}

// Reads an int from the input byte slice.
func readInt(input []byte) int {
	num, numBytes := binary.Varint(input)
	if numBytes <= 0 {
		fmt.Println("Error in reading the int")
	}
	return int(num)
}

// Unmarshal deserializes a byte slice into a SecureIndex.
func Unmarshal(input []byte) SecureIndex {
	var si SecureIndex
	if len(input) < 24 {
		fmt.Println("Cannot unmarshal the bytes into a SecureIndex: Insufficient length")
		return si
	}
	si.DocID = readInt(input[0:8])
	if readInt(input[8:16]) == 256/8 {
		si.Hash = sha256.New
	} else if readInt(input[8:16]) == 512/8 {
		si.Hash = sha512.New
	}
	si.Size, _ = binary.Uvarint(input[16:24])
	var err error
	si.BloomFilter, err = bitarray.Unmarshal(input[24:])
	if err != nil {
		fmt.Println(err)
	}
	return si
}
