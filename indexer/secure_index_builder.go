package indexer

import (
	//"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

// SecureIndexBuilder stores the essential information needed to build the
// indexes for the documents.
type SecureIndexBuilder struct {
	numKeys      uint                  // The number of keys.  This is also the number of PRFs.
	keys         [][]byte              // The keys for the PRFs. Derived from the masterSecret and the salts.
	hash         func() hash.Hash      // The hash function to be used for Hmac.
	trapdoorFunc func(string) [][]byte // The trapdoor function for the words
	size         uint                  // The size of each index, i.e. the number of buckets in the bloom filter.  Smaller size will lead to higher false positive rates.
}

// CreateSecureIndexBuilder instantiates a `secureIndexBuilder`.  Sets up the
// hash function, and derives the keys from the master secret and salts by using
// PBKDF2.  Finally, sets up the trapdoor function for the words.
func CreateSecureIndexBuilder(h func() hash.Hash, masterSecret []byte, salts [][]byte, size uint) *SecureIndexBuilder {
	sIB := new(SecureIndexBuilder)
	sIB.keys = make([][]byte, len(salts))
	for index, salt := range salts {
		sIB.keys[index] = pbkdf2.Key(masterSecret, salt, 4096, 64, sha256.New)
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

/*
func (sIB *SecureIndexBuilder) BuildIndex(documentId uint, document *File) {
	mac := hmacNew(sha256.New, key[0])
	mac.Write([]byte("test"))
	fmt.Println(mac.Sum(nil))
}*/
