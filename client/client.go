package client

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path"
	"search/indexer"
	"search/server"
	"search/util"
	"strconv"
)

// Client stores the necessary information for a client.
type Client struct {
	mountPoint  string                      // Mount point for the client where all the files are stored
	server      *server.Server              // The server that this client is connected to
	indexer     *indexer.SecureIndexBuilder // The indexer for the client
	lookupTable map[string]string           // A map from docuemnt ids to actual filenames
}

// CreateClient instantiates a client connected to Server `s` with a
// `clientNum`.
func CreateClient(s *server.Server, clientNum int, mountPoint string) *Client {
	c := new(Client)

	c.server = s

	// Calculates the master secret and sets up the indexer
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(clientNum)))
	serverKeyHalf := s.GetKeyHalf(clientNum)
	ms := util.XorBytes(h.Sum(nil), serverKeyHalf, len(serverKeyHalf))
	c.indexer = indexer.CreateSecureIndexBuilder(sha256.New, ms, s.GetSalts(), s.GetSize())

	// Initializes the lookup table
	// NOTE: Factor out and add decryption
	c.lookupTable = make(map[string]string)
	if tableContent, found := s.ReadLookupTable(); found {
		json.Unmarshal(tableContent, &c.lookupTable)
	}

	c.mountPoint = mountPoint

	return c
}

// AddFile adds a file to the system.  It first sends the file and index to the
// server, and then stores the file and its lookup entry locally on the client.
// It also updates the lookup table stored on the server.
func (c *Client) AddFile(filename string) {
	content, _ := ioutil.ReadFile(filename)
	docID := c.server.AddFile(content)
	_, file := path.Split(filename)
	c.lookupTable[strconv.Itoa(docID)] = file
	// Write the lookup table to the server
	// NOTE: Factor out and add encryption
	table, _ := json.Marshal(c.lookupTable)
	c.server.WriteLookupTable(table)

	infile, _ := os.Open(filename)
	defer infile.Close()
	si := c.indexer.BuildSecureIndex(docID, infile, len(content))
	c.server.WriteIndex(si)

	outfile, _ := os.Create(path.Join(c.mountPoint, file))
	defer outfile.Close()

	infile.Seek(0, 0)
	io.Copy(outfile, infile)
}

// getFile fetches the file with `docID`, if that file cannot be found on the
// local disk.
func (c *Client) getFile(docID int) {
	// The docID is invalid
	if _, found := c.lookupTable[strconv.Itoa(docID)]; !found {
		return
	}
	filename := path.Join(c.mountPoint, c.lookupTable[strconv.Itoa(docID)])
	// The file exists
	if _, err := os.Stat(filename); err == nil {
		return
	}
	content := c.server.GetFile(docID)
	outfile, _ := os.Create(filename)
	outfile.Write(content)
}
