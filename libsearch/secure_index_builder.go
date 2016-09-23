// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libsearch

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math/big"
	"os"

	"github.com/jxguan/go-datastructures/bitarray"
	"golang.org/x/crypto/pbkdf2"
)

// RandomNumberGenerationFactor is the ratio of the number of random numbers to
// generate to the number of which that we need.  We generate extra random
// numbers to account for those that are out of range.
const RandomNumberGenerationFactor = 1.3

// SecureIndexBuilder stores the essential information needed to build the
// indexes for the documents.
type SecureIndexBuilder struct {
	keys         [][]byte              // The keys for the PRFs. Derived from the masterSecret and the salts.
	hash         func() hash.Hash      // The hash function to be used for HMAC.
	trapdoorFunc func(string) [][]byte // The trapdoor function for the words
	size         uint64                // The size of each index, i.e. the number of buckets in the bloom filter.  Smaller size will lead to higher false positive rates.
}

// CreateSecureIndexBuilder instantiates a `SecureIndexBuilder`.  Sets up the
// hash function, and derives the keys from the master secret and salts by using
// PBKDF2.  Finally, sets up the trapdoor function for the words.
func CreateSecureIndexBuilder(h func() hash.Hash, masterSecret []byte, salts [][]byte, size uint64) *SecureIndexBuilder {
	sib := new(SecureIndexBuilder)
	sib.keys = make([][]byte, len(salts))
	for index, salt := range salts {
		sib.keys[index] = pbkdf2.Key(masterSecret, salt, 4096, 32, sha256.New)
	}
	sib.hash = h
	sib.size = size
	sib.trapdoorFunc = func(word string) [][]byte {
		trapdoors := make([][]byte, len(salts))
		for i := 0; i < len(salts); i++ {
			mac := hmac.New(sib.hash, sib.keys[i])
			mac.Write([]byte(word))
			trapdoors[i] = mac.Sum(nil)
		}
		return trapdoors
	}
	return sib
}

// Builds the bloom filter for the document and returns the result in a sparse
// bit array and the number of unique words in the document.  The result should
// not be directly used as the index, as obfuscation need to be added to the
// bloom filter.
func (sib *SecureIndexBuilder) buildBloomFilter(nonce uint64, document *os.File) (bitarray.BitArray, int64) {
	scanner := bufio.NewScanner(document)
	scanner.Split(bufio.ScanWords)
	bf := bitarray.NewSparseBitArray()
	words := make(map[string]bool)
	for scanner.Scan() {
		word := scanner.Text()
		word = NormalizeKeyword(word)

		if words[word] {
			continue
		}
		words[word] = true
		trapdoors := sib.trapdoorFunc(word)
		for _, trapdoor := range trapdoors {
			mac := hmac.New(sib.hash, trapdoor)
			mac.Write(big.NewInt(int64(nonce)).Bytes())
			codeword, _ := binary.Uvarint(mac.Sum(nil))
			bf.SetBit(codeword % sib.size)
		}
	}
	return bf, int64(len(words))
}

// Blinds the bloom filter by setting random bits to be on for `numIterations`
// iterations.  Instead of using `rand.Read` or `rand.Int` from `crypto/rand`,
// we generate the random numbers in batches to avoid the repeated syscalls in
// the `crypto/rand` functions, which harms the performance.
func (sib *SecureIndexBuilder) blindBloomFilter(bf bitarray.BitArray, numIterations int64) error {
	i := numIterations
	mask := BuildMaskWithLeadingZeroes(GetNumLeadingZeroes(sib.size))
	for i > 0 {
		randNums := make([]uint64, int64(float64(i)*RandomNumberGenerationFactor))
		err := binary.Read(rand.Reader, binary.LittleEndian, &randNums)
		if err != nil {
			return err
		}
		for _, randNum := range randNums {
			actualNum := randNum & mask
			if actualNum < sib.size {
				bf.SetBit(actualNum)
				i--
				if i == 0 {
					break
				}
			}
		}
	}
	return nil
}

// BuildSecureIndex builds the index for `document` and an *encrypted* length of
// `fileLen`.
func (sib *SecureIndexBuilder) BuildSecureIndex(document *os.File, fileLen int64) (SecureIndex, error) {
	nonce, err := RandUint64()
	if err != nil {
		return SecureIndex{}, err
	}
	bf, numUniqWords := sib.buildBloomFilter(nonce, document)
	err = sib.blindBloomFilter(bf, (fileLen-numUniqWords)*int64(len(sib.keys)))
	return SecureIndex{BloomFilter: bf, Nonce: nonce, Size: sib.size, Hash: sib.hash}, err
}

// ComputeTrapdoors computes the trapdoor values for `word`.  This acts as the
// public getter for the trapdoorFunc field of SecureIndexBuilder.
func (sib *SecureIndexBuilder) ComputeTrapdoors(word string) [][]byte {
	return sib.trapdoorFunc(NormalizeKeyword(word))
}
