// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libsearch

import (
	"crypto/sha256"
	"testing"

	"github.com/jxguan/go-datastructures/bitarray"
)

// TestMarshalAndUnmarshal tests the `MarshalBinary` and `UnmarshalBinary`
// functions.  Checks that after a pair of Marshal and Unmarshal operations, the
// orignal SecureIndex is correctly reconstructed from the byte slice.
func TestMarshalAndUnmarshal(t *testing.T) {
	si := new(SecureIndex)
	si.BloomFilter = bitarray.NewSparseBitArray()
	for i := 0; i < 1000; i++ {
		randUint64, err := RandUint64n(1000000)
		if err != nil {
			t.Fatalf("Error when generating random uint64: %s", err)
		}
		si.BloomFilter.SetBit(randUint64)
	}
	si.Size = uint64(1900000)
	si.Nonce = 42
	si.Hash = sha256.New
	bytes, err1 := si.MarshalBinary()
	if err1 != nil {
		t.Fatalf("Error when marshaling the index")
	}
	si2 := new(SecureIndex)
	err2 := si2.UnmarshalBinary(bytes)
	if err2 != nil {
		t.Fatalf("Error when unmarshaling the index")
	}
	if si2.Hash().Size() != si.Hash().Size() {
		t.Fatalf("Hash does not match")
	}
	if si2.Nonce != si.Nonce {
		t.Fatalf("Nonce does not match")
	}
	if si2.Size != si.Size {
		t.Fatalf("Size does not match")
	}
	if !si2.BloomFilter.Equals(si.BloomFilter) {
		t.Fatalf("BloomFilter does not mtach")
	}
}
