package indexer

import (
	"bytes"
	"testing"
)

// Tests `GenerateSalts`.  Makes sure that salts are properly generated.
func TestGenerateSalts(t *testing.T) {
	numKeys := uint(10)
	lenSalt := uint(8)
	salts := GenerateSalts(numKeys, lenSalt)
	for i := uint(0); i < numKeys; i++ {
		if bytes.Equal(salts[i], make([]byte, lenSalt)) {
			t.Fatalf("salt %d is not properly generated", i)
		}
	}
}
