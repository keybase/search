package libsearch

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io/ioutil"
	"os"
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
		r, err := RandUint64n(n)
		if err != nil {
			t.Fatalf("error occurred in generating random uint64: %s", err)
		}
		if r >= n {
			t.Fatalf("random number %d out of range [0, %d)", r, n)
		}
	}
}

// testGetNumLeadingZeroesHelper is the helper function for
// `TestGetNumLeadingZeroes`.  Checks that the call to `GetNumLeadingZeroes`
// returns the expected result.
func testGetNumLeadingZeroesHelper(t *testing.T, num uint64, expected uint) {
	actual := GetNumLeadingZeroes(num)
	if actual != expected {
		t.Fatalf("Incorrect result for GetNumLeadingZeroes(%d): expected %d actual %d", num, expected, actual)
	}
}

// TestGetNumLeadingZeroes tests the `GetNumLeadingZeroes` with various test
// cases.
func TestGetNumLeadingZeroes(t *testing.T) {
	testGetNumLeadingZeroesHelper(t, 0, 64)
	testGetNumLeadingZeroesHelper(t, 1, 63)
	testGetNumLeadingZeroesHelper(t, 3, 62)
	testGetNumLeadingZeroesHelper(t, 4, 61)
	testGetNumLeadingZeroesHelper(t, 1023, 54)
	testGetNumLeadingZeroesHelper(t, 1024, 53)
	testGetNumLeadingZeroesHelper(t, ^uint64(0), 0)
}

// testBuildMaskWithLeadingZeroesHelper is the helper function for
// `TestBuildMaskWithLeadingZeroes`.  Checks that the call to
// `BuildMaskWithLeadingZeroes` returns the expected result.
func testBuildMaskWithLeadingZeroesHelper(t *testing.T, numZeroes uint, expected uint64) {
	actual := BuildMaskWithLeadingZeroes(numZeroes)
	if actual != expected {
		t.Fatalf("Incorrect result for BuildMaskWithLeadingZeroes(%d): expected %d actual %d", numZeroes, expected, actual)
	}
}

// TestBuildMaskWithLeadingZeroes tests the `BuildMaskWithLeadingZeroes`
// function with various test cases.
func TestBuildMaskWithLeadingZeroes(t *testing.T) {
	testBuildMaskWithLeadingZeroesHelper(t, 0, ^uint64(0))
	testBuildMaskWithLeadingZeroesHelper(t, 64, 0)
	testBuildMaskWithLeadingZeroesHelper(t, 62, 3)
	testBuildMaskWithLeadingZeroesHelper(t, 54, 1023)
}

// Tests the `RandUint64n` function.  Checks that the random uint64's generated
// are within the ranges.
func TestRandUint64n(t *testing.T) {
	checkRandUint64nForNum(uint64(42), t)
	checkRandUint64nForNum(uint64(123456789), t)
	checkRandUint64nForNum(uint64(1), t)
	checkRandUint64nForNum(^uint64(0), t)
}

// Tests the `RandUint64` function.  Checks that no errors are produced.
func TestRandUint64(t *testing.T) {
	for i := 0; i < 10000; i++ {
		_, err := RandUint64()
		if err != nil {
			t.Fatalf("error occurred in generating random uint64: %s", err)
		}
	}
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

// TestReadInt tests the `readInt` function.  Checks that the correct integer is
// read.
func TestReadInt(t *testing.T) {
	expected := 42
	byteSlice := make([]byte, 8)
	binary.PutVarint(byteSlice, int64(expected))
	actual, err := readInt(byteSlice)
	if err != nil {
		t.Fatalf("error when reading the interger: %s", err)
	}
	if expected != actual {
		t.Fatalf("readInt does not yield the original integer")
	}
}

// TestWriteFileAtomic tests the `WriteFileAtomic` function.  Checks that the
// files are properly written.
func TestWriteFileAtomic(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "writeFileTest")
	if err != nil {
		t.Fatalf("error when creating the temporary testfile: %s", err)
	}
	defer os.Remove(tmpFile.Name())

	contentString := "This is a random test string"

	if err = WriteFileAtomic(tmpFile.Name(), []byte(contentString)); err != nil {
		t.Fatalf("error when writing the file: %s", err)
	}

	contentRead, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("error when reading the file: %s", err)
	}

	if string(contentRead) != contentString {
		t.Fatalf("incorrect content is written to the file")
	}
}

// testNormalizeKeywordHelper is the helper function for `TestNormalizeKeyword`.
// Checks that calling `NormalizeKeyword` with `original` yields `expected` as
// the result.
func testNormalizeKeywordHelper(t *testing.T, original, expected string) {
	actual := NormalizeKeyword(original)
	if actual != expected {
		t.Fatalf("incorrect result for NormalizeKeyword(%s): expected \"%s\", actual \"%s\"", original, expected, actual)
	}
}

// TestNormalizeKeyword tests the `NormalizeKeyword` function.  Checks that the
// desired normalized strings are returned.
func TestNormalizeKeyword(t *testing.T) {
	testNormalizeKeywordHelper(t, "", "") // Makes sure that empty strings woudln't crash
	testNormalizeKeywordHelper(t, ".,;'[]'", "")
	testNormalizeKeywordHelper(t, "iCe-CREAm", "icecream")
	testNormalizeKeywordHelper(t, "Yoo!!!!!!", "yoo")
	testNormalizeKeywordHelper(t, "SHA-256", "sha256")
	testNormalizeKeywordHelper(t, "Español!", "español")
	testNormalizeKeywordHelper(t, "苟利国家生死以！", "苟利国家生死以")
}

// TestDocID tests the `PathnameToDocID` and the `DocIDToPathname` functions.
// Checks that the orginal pathname is retrieved after encrypting and
// decrypting, and that decrypting with a different key yields an error.
func TestDocID(t *testing.T) {
	var key1, key2 [32]byte
	_, err := rand.Read(key1[:])
	if err != nil {
		t.Fatalf("error when generating key: %s", err)
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		t.Fatalf("error when generating key: %s", err)
	}

	pathname := "path/to/a/test/file"

	docID, err := PathnameToDocID(1, pathname, key1)
	if err != nil {
		t.Fatalf("error when encrypting the pathname: %s", err)
	}

	pathnameRetrieved, err := DocIDToPathname(docID, [][32]byte{key1})
	if err != nil {
		t.Fatalf("error when decrypting the pathname: %s", err)
	}

	if pathname != pathnameRetrieved {
		t.Fatalf("encrypting and then decrypting does not yield the original pathname")
	}

	pathname2, err := DocIDToPathname(docID, [][32]byte{key2})
	if err == nil && pathname == pathname2 {
		t.Fatalf("encrypted pathname decrypted with a different key")
	}
}

// testNextPowerOfTwoHelper checks that `nextPowerOfTwo(n) == expected`.
func testNextPowerOfTwoHelper(t *testing.T, n uint32, expected uint32) {
	actual := nextPowerOfTwo(n)
	if actual != expected {
		t.Fatalf("incorrect result of nextPowerOfTwo(%d): expected %d actual %d", n, expected, actual)
	}
}

// TestNextPowerOfTwo tests the `nextPowerOfTwo` function.  Checks that all the
// results are as expected.
func TestNextPowerOfTwo(t *testing.T) {
	testNextPowerOfTwoHelper(t, 5, 8)
	testNextPowerOfTwoHelper(t, 4, 8)
	testNextPowerOfTwoHelper(t, 1, 2)
	testNextPowerOfTwoHelper(t, 7, 8)
	testNextPowerOfTwoHelper(t, 17, 32)
}

// TestPadding tests the `padPathname` and the `depadPathname` functions.
// Checks that the same pathname is retrieved after padding and depadding.
func TestPadding(t *testing.T) {
	pathname := "simply/a/random/path/without/padding"

	paddedPathname, err := padPathname(pathname)
	if err != nil {
		t.Fatalf("error when padding the pathname: %s", err)
	}

	depaddedPathname, err := depadPathname(paddedPathname)
	if err != nil {
		t.Fatalf("error when depadding the pathname: %s", err)
	}

	if pathname != depaddedPathname {
		t.Fatalf("incorrect pathname after padding and depadding")
	}
}
