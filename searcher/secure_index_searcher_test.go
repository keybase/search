package searcher

import (
	"crypto/sha256"
	"io/ioutil"
	"os"
	"search/indexer"
	"strings"
	"testing"
)

// Tests the `SearchSecureIndex` function.  Checks that searching for words
// within the document returns true, and words that are not in the document
// yields false (with high probability).
func TestSearchSecureIndex(t *testing.T) {
	numKeys := 13
	lenSalt := uint(8)
	size := uint64(1900000)
	salts := indexer.GenerateSalts(numKeys, lenSalt)
	sib := indexer.CreateSecureIndexBuilder(sha256.New, []byte("test"), salts, size)
	doc, err := ioutil.TempFile("", "indexTest")
	docContent := "This is a test file. It has a pretty random content."
	docWords := strings.Split(docContent, " ")
	docID := uint(42)
	if err != nil {
		t.Errorf("cannot create the temporary test file for `TestSearchSecureIndex`")
	}
	defer os.Remove(doc.Name()) // clean up
	if _, err := doc.Write([]byte(docContent)); err != nil {
		t.Errorf("cannot write to the temporary test file for `TestSearchSecureIndex")
	}
	// Rewinds the file
	if _, err := doc.Seek(0, 0); err != nil {
		t.Errorf("cannot rewind the temporary test file for `TestSearchSecureIndex")
	}
	index := sib.BuildSecureIndex(docID, doc, len(docContent))
	for _, word := range docWords {
		if !SearchSecureIndex(index, sib.ComputeTrapdoors(word)) {
			t.Fatalf("one or more words cannot be found in the index")
		}
	}

	numFound := 0
	for i := 0; i < 10000; i++ {
		if SearchSecureIndex(index, sib.ComputeTrapdoors("nonDocWord"+string(i))) {
			numFound++
		}
	}
	if numFound > 1 {
		t.Fatalf("multiple false positives reported")
	}
}
