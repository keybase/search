package client

import (
	"crypto/sha256"
	"encoding/json"
	"search/indexer"
	"search/server"
	"search/util"
	"strconv"
)

// Client stores the necessary information for a client.
type Client struct {
	server      *server.Server              // The server that this client is connected to
	indexer     *indexer.SecureIndexBuilder // The indexer for the client
	lookupTable map[string]string           // A map from docuemnt ids to actual filenames
}

// CreateClient instantiates a client connected to Server `s` with a
// `clientNum`.
func CreateClient(s *server.Server, clientNum int) *Client {
	c := new(Client)

	c.server = s

	// Calculates the master secret and sets up the indexer
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(clientNum)))
	serverKeyHalf := s.GetKeyHalf(clientNum)
	ms := util.XorBytes(h.Sum(nil), serverKeyHalf, len(serverKeyHalf))
	c.indexer = indexer.CreateSecureIndexBuilder(sha256.New, ms, s.GetSalts(), s.GetSize())

	// Initializes the lookup table
	c.lookupTable = make(map[string]string)
	if tableContent, found := s.ReadLookupTable(); found {
		json.Unmarshal(tableContent, c.lookupTable)
	}

	return c
}
