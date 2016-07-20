package client

import (
	"io/ioutil"
	"os"
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

// TestCreateClient tests the `CreateClient` function.  Checks that multiple
// clients created for the server should behave the same regardless of the
// different client numbers.
func TestCreateClient(t *testing.T) {
	s, dir := createTestServer(5, 8, 8, 0.000001, uint64(100000))
	defer os.RemoveAll(dir)

	c1 := CreateClient(s, 0)
	c2 := CreateClient(s, 1)

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
