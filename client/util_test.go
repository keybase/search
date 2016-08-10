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

	docID, err := pathnameToDocID(pathname, &key1)
	if err != nil {
		t.Fatalf("error when encrypting the pathname: %s", err)
	}

	pathnameRetrieved, err := docIDToPathname(docID, &key1)
	if err != nil {
		t.Fatalf("error when decrypting the pathname: %s", err)
	}

	if pathname != pathnameRetrieved {
		t.Fatalf("encrypting and then decrypting does not yield the original pathname")
	}

	pathname2, err := docIDToPathname(docID, &key2)
	if err == nil && pathname == pathname2 {
		t.Fatalf("encrypted pathname decrypted with a different key")
	}
}

func TestNextPowerOfTwo(t *testing.T)

func TestPadding(t *testing.T) {

}
