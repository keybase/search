package libsearch

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Tests `GenerateSalts`.  Makes sure that salts are properly generated.
func TestGenerateSalts(t *testing.T) {
	numKeys := 10
	lenSalt := 8
	salts, err := GenerateSalts(numKeys, lenSalt)
	if err != nil {
		t.Fatalf("error raised when generating salts")
	}
	for i := 0; i < numKeys; i++ {
		if bytes.Equal(salts[i], make([]byte, lenSalt)) {
			t.Fatalf("salt %d is not properly generated", i)
		}
	}
}

// Checks that random numbers generated are within the range of [0, n).
func checkRandUint64nForNum(n uint64, t *testing.T) {
	for i := 0; i < 10000; i++ {
		r := RandUint64n(n)
		if r >= n {
			t.Fatalf("random number %d out of range [0, %d)", r, n)
		}
	}
}

// Tests the `randUint64n` function.  Checks that the random uint64's generated
// are within the ranges.
func TestRandUint64n(t *testing.T) {
	checkRandUint64nForNum(uint64(42), t)
	checkRandUint64nForNum(uint64(123456789), t)
	checkRandUint64nForNum(uint64(1), t)
	checkRandUint64nForNum(^uint64(0), t)
}

// Tests the `XorBytes` function.  Checks that after xor'ing with the same bytes
// twice, we can get the oringal bytes.
func TestXorBytes(t *testing.T) {
	for i := 0; i < 100; i++ {
		one := make([]byte, 64)
		two := make([]byte, 64)
		rand.Read(one)
		rand.Read(two)
		result := XorBytes(one, two, 64)
		if !bytes.Equal(XorBytes(one, result, 64), two) {
			t.Fatalf("xor'ing twice does not give back the orignal array")
		}
	}
}
