package client

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"search/server"
	"testing"
)

// createTestServer creates a test server with the params.  Need to manually
// remove the directory in the second return value.
func createTestServer(numClients, lenMS, lenSalt int, fpRate float64, numUniqWords uint64) (*server.Server, string) {
	dir, err := ioutil.TempDir("", "serverTest")
	if err != nil {
		panic("cannot create the temporary test directory")
	}
	s := server.CreateServer(numClients, lenMS, lenSalt, dir, fpRate, numUniqWords)
	return s, dir
}

// createTestClient creates a test client with the params.  Need to manually
// remove the directory in the second return value.
func createTestClient(s *server.Server, clientNum int) (*Client, string) {
	dir, err := ioutil.TempDir("", "clientTest")
	if err != nil {
		panic("cannot create the temporary test directory")
	}
	c := CreateClient(s, clientNum, dir)
	return c, dir
}

// createTestFile creates a temporary file with `content` and returns the
// filename as a string.  The file need to be manually removed by the caller.
func createTestFile(content string) string {
	doc, err := ioutil.TempFile("", "testFile")
	if err != nil {
		panic("cannot create the temporary test file")
	}
	if _, err := doc.Write([]byte(content)); err != nil {
		panic("cannot write to the temporary test file")
	}
	return doc.Name()
}

// TestCreateClient tests the `CreateClient` function.  Checks that multiple
// clients created for the server should behave the same regardless of the
// different client numbers, (except for mount point).
func TestCreateClient(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
	defer os.RemoveAll(dir)

	c1 := CreateClient(s, 0, "unused")
	c2 := CreateClient(s, 1, "unused")

	if c1.server != c2.server {
		t.Fatalf("different servers for the clients")
	}
	if !reflect.DeepEqual(c1.lookupTable, c2.lookupTable) {
		t.Fatalf("different lookup tables for the clients")
	}
	if !reflect.DeepEqual(c1.indexer.ComputeTrapdoors("testing"), c2.indexer.ComputeTrapdoors("testing")) {
		t.Fatalf("different indexers for the clients")
	}
}

// TestAddFile tests the `AddFile` function.  Checks that the lookup tables are
// correctly updated on both the server and the client, and that the file is
// written correctly both on the client and the server and that the index is
// correctly written on the server.
func TestAddFile(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
	defer os.RemoveAll(dir)

	c, cliDir := createTestClient(s, 0)
	defer os.RemoveAll(cliDir)

	content := "This is a simple test file"
	file := createTestFile(content)
	_, filename := path.Split(file)
	defer os.Remove(file)

	c.AddFile(file)

	if c.lookupTable["0"] != filename {
		t.Fatalf("lookup table not set up correctly on the client")
	}

	serverLookupTable := make(map[string]string)
	if tableContent, found := s.ReadLookupTable(); found {
		json.Unmarshal(tableContent, &serverLookupTable)
	}
	if serverLookupTable["0"] != filename {
		t.Fatalf("lookup table not set up correctly on the server")
	}

	if !bytes.Equal(s.GetFile(0), []byte(content)) {
		t.Fatalf("file not written correctly to the server")
	}

	if !reflect.DeepEqual(s.SearchWord(c.indexer.ComputeTrapdoors("simple")), []int{0}) {
		t.Fatalf("index file not written correctly to server")
	}

	contentRead, err := ioutil.ReadFile(path.Join(cliDir, filename))
	if err != nil || !bytes.Equal(contentRead, []byte(content)) {
		t.Fatalf("file not correctly written to local client storage")
	}
}
