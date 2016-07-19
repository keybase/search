package server

import (
	"bytes"
	"crypto/sha256"
	"io/ioutil"
	"os"
	"path"
	"search/index"
	"search/indexer"
	"search/util"
	"strconv"
	"testing"
)

// Calculates the master secret for client with `clientNum`, and the given
// `serverKeyHalf`.  This is the helper function to utilize the tests.
func calculateMasterSecret(clientNum int, serverKeyHalf []byte) []byte {
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(clientNum)))
	return util.XorBytes(h.Sum(nil), serverKeyHalf, len(serverKeyHalf))
}

// createTestServer creates a test server with the params.  Need to manually
// remove the directory in the second return value.
func createTestServer(numClients, lenMS, lenSalt int, fpRate float64) (*Server, string) {
	dir, err := ioutil.TempDir("", "serverTest")
	if err != nil {
		panic("cannot create the temporary test directory")
	}
	s := CreateServer(numClients, lenMS, lenSalt, dir, fpRate)
	return s, dir
}

// Tests the `CreateServer` function.  Checks that all the fields in the server
// struct are correctly set up.
func TestCreateServer(t *testing.T) {
	numClients := 5
	lenMS := 8
	lenSalt := 8
	fpRate := 0.000001
	expectedR := 20
	s, dir := createTestServer(numClients, lenMS, lenSalt, fpRate)
	defer os.RemoveAll(dir)

	if numClients != len(s.keyHalves) {
		t.Fatalf("incorrect number of server-side key halves")
	}
	if lenMS != len(s.keyHalves[0]) {
		t.Fatalf("incorrect length of the master secret being generated")
	}
	if lenMS != s.lenMS {
		t.Fatalf("incorrect length of the master secret")
	}
	if expectedR != len(s.salts) {
		t.Fatalf("incorrect number of salts generated")
	}
	if lenSalt != len(s.salts[0]) {
		t.Fatalf("incorrect length of the salts")
	}
	if s.numFiles != 0 {
		t.Fatalf("number of files not initialized to zero")
	}
	if dir != s.mountPoint {
		t.Fatalf("server mount point not set up correctly")
	}
	ms := calculateMasterSecret(0, s.keyHalves[0])
	for i := 1; i < numClients; i++ {
		msCpy := calculateMasterSecret(i, s.keyHalves[i])
		if !bytes.Equal(ms, msCpy) {
			t.Fatalf("different master secrets derived from different clients")
		}
	}
}

// TestAddFile tests the `AddFile` function.  Checks that the content can be
// correctly retrieved and the document IDs returned are correct.
func TestAddFile(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001)
	defer os.RemoveAll(dir)

	files := [][]byte{
		[]byte("This is the very first file."),
		[]byte("Then comes the second."),
		[]byte("Now the third.")}

	for i := 0; i < 3; i++ {
		if s.AddFile(files[i]) != i {
			t.Fatalf("incorrect number of files returned")
		}
	}

	for i := 0; i < 3; i++ {
		file, err := os.Open(path.Join(dir, strconv.Itoa(i)))
		if err != nil {
			t.Fatalf("error in reading the stored files")
		}
		content, err := ioutil.ReadAll(file)
		if err != nil {
			t.Fatalf("error in reading the stored files")
		}
		if !bytes.Equal(content, files[i]) {
			t.Fatalf("content in the file does not match")
		}
		file.Close()
	}
}

// buildIndexForFile builds an index for a file with `content` and `docID`.  The
// server `s` is needed for retrieving the master secret.
func buildIndexForFile(s *Server, content string, docID int) index.SecureIndex {
	size := uint64(1900000)
	sib := indexer.CreateSecureIndexBuilder(sha256.New, calculateMasterSecret(0, s.keyHalves[0]), s.salts, size)
	doc, err := ioutil.TempFile("", "indexTest")
	if err != nil {
		panic("cannot create the temporary test file")
	}
	defer os.Remove(doc.Name()) // clean up
	if _, err := doc.Write([]byte(content)); err != nil {
		panic("cannot write to the temporary test file")
	}
	// Rewinds the file
	if _, err := doc.Seek(0, 0); err != nil {
		panic("cannot rewind the temporary test file")
	}
	si := sib.BuildSecureIndex(docID, doc, len(content))
	return si
}

// TestWriteAndReadIndex tests the `WriteIndex` and `readIndex` functions.
// Checks that the orignal SecureIndex is retrieved after writing to and reading
// from the disk.
func TestWriteAndReadIndex(t *testing.T) {
	// Initialize the server
	s, dir := createTestServer(5, 8, 8, 0.000001)
	defer os.RemoveAll(dir)

	si := buildIndexForFile(s, "This is a random test file.", 0)

	s.WriteIndex(si)
	si2 := s.readIndex(0)

	// Check that the indexes are the same
	if si2.DocID != si.DocID {
		t.Fatalf("DocID does not match")
	}
	if si2.Hash().Size() != si.Hash().Size() {
		t.Fatalf("Hash does not match")
	}
	if si2.Size != si.Size {
		t.Fatalf("Size does not match")
	}
	if !si2.BloomFilter.Equals(si.BloomFilter) {
		t.Fatalf("BloomFilter does not mtach")
	}
}
