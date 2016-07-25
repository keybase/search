package server

import (
	"bytes"
	"crypto/sha256"
	"io/ioutil"
	"os"
	"reflect"
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
func createTestServer(numClients, lenMS, lenSalt int, fpRate float64, numUniqWords uint64) (*Server, string) {
	dir, err := ioutil.TempDir("", "serverTest")
	if err != nil {
		panic("cannot create the temporary test directory")
	}
	s, err2 := CreateServer(numClients, lenMS, lenSalt, dir, fpRate, numUniqWords)
	if err2 != nil {
		panic("error when creating the server")
	}

	return s, dir
}

// Tests the `CreateServer` function.  Checks that all the fields in the server
// struct are correctly set up.
func TestCreateServer(t *testing.T) {
	numClients := 5
	lenMS := 8
	lenSalt := 8
	fpRate := 0.000001
	numUniqWords := uint64(100000)
	expectedR := 20
	expectedSize := uint64(2885391)
	s, dir := createTestServer(numClients, lenMS, lenSalt, fpRate, numUniqWords)
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
	if expectedSize != s.size {
		t.Fatalf("incorrect size of the server")
	}
	if lenSalt != len(s.salts[0]) {
		t.Fatalf("incorrect length of the salts")
	}
	if s.numFiles != 0 {
		t.Fatalf("number of files not initialized to zero")
	}
	if dir != s.directory {
		t.Fatalf("server directory not set up correctly")
	}
	ms := calculateMasterSecret(0, s.keyHalves[0])
	for i := 1; i < numClients; i++ {
		msCpy := calculateMasterSecret(i, s.keyHalves[i])
		if !bytes.Equal(ms, msCpy) {
			t.Fatalf("different master secrets derived from different clients")
		}
	}
}

// TestAddAndGetFile tests the `AddFile` and `GetFile` functions.  Checks that
// the content can be correctly retrieved and the document IDs returned are
// correct.
func TestAddAndGetFile(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
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
		content := s.GetFile(i)
		if !bytes.Equal(content, files[i]) {
			t.Fatalf("content in the file does not match")
		}
	}
}

// buildIndexForFile builds an index for a file with `content` and `docID` using
// the SecureIndexBuilder `sib`.
func buildIndexForFile(sib *indexer.SecureIndexBuilder, content string, docID int) index.SecureIndex {
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
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
	defer os.RemoveAll(dir)
	sib := indexer.CreateSecureIndexBuilder(sha256.New, calculateMasterSecret(0, s.keyHalves[0]), s.salts, s.size)

	si := buildIndexForFile(sib, "This is a random test file.", 0)

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

// TestSearchWord tests the `SearchWord` function.  Checks that the correct set
// of files are returned when searching for a word on the server.
func TestSearchWord(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
	defer os.RemoveAll(dir)
	sib := indexer.CreateSecureIndexBuilder(sha256.New, calculateMasterSecret(0, s.keyHalves[0]), s.salts, s.size)

	files := []string{
		"charmander pikachu bulbasaur",
		"pikachu squirtle",
		"",
		"squirtle charmander bulbasaur",
		"bulbasaur charmander squirtle pikachu"}

	for i := 0; i < len(files); i++ {
		s.AddFile([]byte(files[i]))
		si := buildIndexForFile(sib, files[i], i)
		s.WriteIndex(si)
	}

	expected := []int{0, 1, 4}
	actual := s.SearchWord(sib.ComputeTrapdoors("pikachu"))

	if len(expected) != len(actual) {
		t.Fatalf("incorrect number of files found")
	}

	for i := 0; i < len(expected); i++ {
		if expected[i] != actual[i] {
			t.Fatalf("incorrect file found")
		}
	}
}

// TestWriteAndReadLookupTable tests the `WriteLookupTable` and
// `ReadLookupTable` functions.  Checks that the original content is read,  even
// after mutiple writes.  If the lookup table is not present, makes sure that
// `ReadLookupTable` returns false.
func TestWriteAndReadLookupTable(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
	defer os.RemoveAll(dir)

	if _, found := s.ReadLookupTable(); found {
		t.Fatalf("retuns true before lookupTable is written")
	}

	content := "This is a test string"
	s.WriteLookupTable([]byte(content))
	actual, found := s.ReadLookupTable()
	if !found || !bytes.Equal([]byte(content), actual) {
		t.Fatalf("incorrect lookup table content")
	}

	content2 := "This is a different test string"
	s.WriteLookupTable([]byte(content2))
	actual2, found2 := s.ReadLookupTable()
	if !found2 || !bytes.Equal([]byte(content2), actual2) {
		t.Fatalf("incorrect lookup table content after second write")
	}
}

// TestWriteToFileAndLoadServer tests the `writeToFile` and `LoadServer`
// functions.  Checks that after writing to file, the original server status can
// be restored by calling `LoadServer`.
func TestWriteToFileAndLoadServer(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
	defer os.RemoveAll(dir)
	s.numFiles = 42
	s.writeToFile()
	s2 := LoadServer(dir)
	if !reflect.DeepEqual(s, s2) {
		t.Fatalf("different server after loading from file")
	}
}
