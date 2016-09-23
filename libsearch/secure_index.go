// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libsearch

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
	Nonce       uint64
	Size        uint64           // The number of buckets in the bloom filter.
	Hash        func() hash.Hash // The hash function to be used for HMAC.
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (si *SecureIndex) MarshalBinary() ([]byte, error) {
	bfBytes, err := bitarray.Marshal(si.BloomFilter)
	if err != nil {
		return nil, err
	}
	length := 3*binary.MaxVarintLen64 + len(bfBytes)
	result := make([]byte, length)
	binary.PutVarint(result[0:], int64(si.Hash().Size()))
	binary.PutUvarint(result[binary.MaxVarintLen64:], si.Nonce)
	binary.PutUvarint(result[2*binary.MaxVarintLen64:], si.Size)
	copy(result[3*binary.MaxVarintLen64:], bfBytes)
	return result, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (si *SecureIndex) UnmarshalBinary(input []byte) error {
	if len(input) < 3*binary.MaxVarintLen64 {
		return errors.New("insufficient binary length")
	}
	var err error
	hashLen, err := readInt(input[0:binary.MaxVarintLen64])
	if err != nil {
		return err
	} else if hashLen == 256/8 {
		si.Hash = sha256.New
	} else if hashLen == 512/8 {
		si.Hash = sha512.New
	} else {
		return errors.New("invalid hash function length")
	}
	si.Nonce, _ = binary.Uvarint(input[binary.MaxVarintLen64 : 2*binary.MaxVarintLen64])
	si.Size, _ = binary.Uvarint(input[2*binary.MaxVarintLen64 : 3*binary.MaxVarintLen64])
	si.BloomFilter, err = bitarray.Unmarshal(input[3*binary.MaxVarintLen64:])
	if err != nil {
		return err
	}
	return nil
}
