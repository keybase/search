package client

import (
	"crypto/rand"
	"testing"
)

// TestDocID tests the `pathnameToDocID` and the `docIDToPathname` functions.
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

	docID, err := pathnameToDocID(pathname, key1)
	if err != nil {
		t.Fatalf("error when encrypting the pathname: %s", err)
	}

	pathnameRetrieved, err := docIDToPathname(docID, key1)
	if err != nil {
		t.Fatalf("error when decrypting the pathname: %s", err)
	}

	if pathname != pathnameRetrieved {
		t.Fatalf("encrypting and then decrypting does not yield the original pathname")
	}

	pathname2, err := docIDToPathname(docID, key2)
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

// testRelPathStrictHelper checks that the call to `relPathStrict` with
// `basepath` and `targpath` yields the `expected` result and that the error
// status matches the `isError` boolean.
func testRelPathStrictHelper(t *testing.T, basepath, targpath, expected string, isError bool) {
	actual, err := relPathStrict(basepath, targpath)
	if isError {
		if err == nil {
			t.Fatalf("expecting error for basepath \"%s\" and targpath \"%s\", no error returned", basepath, targpath)
		}
	} else if err != nil {
		t.Fatalf("unexpected error for basepath \"%s\" and targpath \"%s\"", basepath, targpath)
	} else if actual != expected {
		t.Fatalf("incorrect relative path for basepath \"%s\" and targpath \"%s\", expected \"%s\", actual \"%s\"", basepath, targpath, expected, actual)
	}
}

// TestRelPathStrict tests multiple edge cases for the `relPathStrict` function.
func TestRelPathStrict(t *testing.T) {
	testRelPathStrictHelper(t, "test", "test/valid", "valid", false)
	testRelPathStrictHelper(t, "test", "test/multiple/folders/valid", "multiple/folders/valid", false)
	testRelPathStrictHelper(t, "test", "test/../dotdotinvalid", "", true)
	testRelPathStrictHelper(t, "test", "test/test/../../dotdotinvalid", "", true)
	testRelPathStrictHelper(t, "test", "test/../test/dotdotvalid", "dotdotvalid", false)
	testRelPathStrictHelper(t, "/abs", "/abs/valid", "valid", false)
	testRelPathStrictHelper(t, "test", "totallyinvalid", "", true)
	testRelPathStrictHelper(t, "reverse/invalid", "reverse", "", true)
}
