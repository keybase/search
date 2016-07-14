package searcher

import (
	"crypto/hmac"
	"encoding/binary"
	"search/index"
)

// SearchSecureIndex searches the index `secIndex` for a word with `trapdoors`,
// and returns true if the word has been found, and false otherwise.
// Note: False positives are possible.
func SearchSecureIndex(secIndex index.SecureIndex, trapdoors [][]byte) bool {
	for _, trapdoor := range trapdoors {
		mac := hmac.New(secIndex.Hash, trapdoor)
		mac.Write([]byte(string(secIndex.DocID)))
		// Ignore the error as we need to truncate the 256-bit hash into 64 bits
		codeword, _ := binary.Uvarint(mac.Sum(nil))
		if found, _ := secIndex.BloomFilter.GetBit(codeword % secIndex.Size); !found {
			return false
		}
	}
	return true
}
