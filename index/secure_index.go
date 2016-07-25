package index

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
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

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (si *SecureIndex) MarshalBinary() ([]byte, error) {
	bfBytes, err := bitarray.Marshal(si.BloomFilter)
	if err != nil {
		return nil, err
	}
	length := 24 + len(bfBytes)
	result := make([]byte, length)
	binary.PutVarint(result, int64(si.DocID))
	binary.PutVarint(result[8:], int64(si.Hash().Size()))
	binary.PutUvarint(result[16:], si.Size)
	copy(result[24:], bfBytes)
	return result, nil
}

// Reads an int from the input byte slice.
func readInt(input []byte) (int, error) {
	num, numBytes := binary.Varint(input)
	if numBytes <= 0 {
		return 0, errors.New("cannot read the int")
	}
	return int(num), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (si *SecureIndex) UnmarshalBinary(input []byte) error {
	if len(input) < 24 {
		return errors.New("insufficient binary length")
	}
	var err error
	si.DocID, err = readInt(input[0:8])
	if err != nil {
		return err
	}
	var hashLen int
	hashLen, err = readInt(input[8:16])
	if err != nil {
		return err
	} else if hashLen == 256/8 {
		si.Hash = sha256.New
	} else if hashLen == 512/8 {
		si.Hash = sha512.New
	}
	si.Size, _ = binary.Uvarint(input[16:24])
	si.BloomFilter, err = bitarray.Unmarshal(input[24:])
	if err != nil {
		return err
	}
	return nil
}
