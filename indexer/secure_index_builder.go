package indexer

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"github.com/golang-collections/go-datastructures/bitarray"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"os"
)

// SecureIndexBuilder stores the essential information needed to build the
// indexes for the documents.
type SecureIndexBuilder struct {
	numKeys      uint                  // The number of keys.  This is also the number of PRFs.
	keys         [][]byte              // The keys for the PRFs. Derived from the masterSecret and the salts.
	hash         func() hash.Hash      // The hash function to be used for Hmac.
	trapdoorFunc func(string) [][]byte // The trapdoor function for the words
	size         uint64                // The size of each index, i.e. the number of buckets in the bloom filter.  Smaller size will lead to higher false positive rates.
}

// CreateSecureIndexBuilder instantiates a `secureIndexBuilder`.  Sets up the
// hash function, and derives the keys from the master secret and salts by using
// PBKDF2.  Finally, sets up the trapdoor function for the words.
func CreateSecureIndexBuilder(h func() hash.Hash, masterSecret []byte, salts [][]byte, size uint64) *SecureIndexBuilder {
	sIB := new(SecureIndexBuilder)
	sIB.keys = make([][]byte, len(salts))
	for index, salt := range salts {
		sIB.keys[index] = pbkdf2.Key(masterSecret, salt, 4096, 32, sha256.New)
	}
	sIB.hash = h
	sIB.numKeys = uint(len(salts))
	sIB.size = size
	sIB.trapdoorFunc = func(word string) [][]byte {
		trapdoors := make([][]byte, sIB.numKeys)
		for i := uint(0); i < sIB.numKeys; i++ {
			mac := hmac.New(sIB.hash, sIB.keys[i])
			mac.Write([]byte(word))
			trapdoors[i] = mac.Sum(nil)
		}
		return trapdoors
	}
	return sIB
}

// Builds the bloom filter for the document and returns the result in a sparse
// bit array and the number of unique words in the document.  The result should
// not be directly used as the index, as obfuscation need to be added to the
// bloom filter.
func (sIB *SecureIndexBuilder) buildBloomFilter(docID uint, document *os.File) (bitarray.BitArray, int) {
	scanner := bufio.NewScanner(document)
	scanner.Split(bufio.ScanWords)
	bf := bitarray.NewSparseBitArray()
	words := make(map[string]bool)
	for scanner.Scan() {
		word := scanner.Text()
		words[word] = true
		trapdoors := sIB.trapdoorFunc(word)
		for _, trapdoor := range trapdoors {
			mac := hmac.New(sIB.hash, trapdoor)
			mac.Write([]byte(string(docID)))
			// Ignore the error as we need to truncate the 256-bit hash into 64 bits
			codeword, _ := binary.Uvarint(mac.Sum(nil))
			bf.SetBit(codeword % sIB.size)
		}
	}
	return bf, len(words)
}
