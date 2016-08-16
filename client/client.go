package client

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"

	rpc "github.com/keybase/go-framed-msgpack-rpc"
	"github.com/keybase/search/libsearch"
	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/net/context"
)

// Client contains all the necessary information for a KBFS Search Client.
type Client struct {
	searchCli   sserver1.SearchServerClient   // The client that talks to the RPC Search Server.
	directory   string                        // The directory where KBFS is mounted.
	indexer     *libsearch.SecureIndexBuilder // The indexer for the client.
	pathnameKey [32]byte                      // The key to encrypt and decrypt the pathnames to/from document IDs.
}

// CreateClient creates a new `Client` instance with the parameters and returns
// a pointer the the instance.  Returns an error on any failue.
func CreateClient(ipAddr string, port int, masterSecret []byte, directory string) (*Client, error) {
	c, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ipAddr, port))
	if err != nil {
		return nil, err
	}
	xp := rpc.NewTransport(c, nil, nil)

	searchCli := sserver1.SearchServerClient{Cli: rpc.NewClient(xp, nil)}

	salts, err := searchCli.GetSalts(context.TODO())
	if err != nil {
		return nil, err
	}

	size, err := searchCli.GetSize(context.TODO())
	if err != nil {
		return nil, err
	}

	indexer := libsearch.CreateSecureIndexBuilder(sha256.New, masterSecret, salts, uint64(size))

	var pathnameKey [32]byte
	copy(pathnameKey[:], masterSecret[0:32])

	absDir, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}

	cli := new(Client)
	*cli = Client{
		searchCli:   searchCli,
		directory:   absDir,
		indexer:     indexer,
		pathnameKey: pathnameKey,
	}

	return cli, nil
}

// AddFile indexes a file with the given `pathname` and writes the index to the
// server.
func (c *Client) AddFile(pathname string) error {
	relPath, err := relPathStrict(c.directory, pathname)
	if err != nil {
		return err
	}

	docID, err := pathnameToDocID(relPath, c.pathnameKey)
	if err != nil {
		return err
	}

	file, err := os.Open(pathname)
	if err != nil {
		return err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	secIndex, err := c.indexer.BuildSecureIndex(file, fileInfo.Size())
	if err != nil {
		return err
	}

	secIndexBytes, err := secIndex.MarshalBinary()
	if err != nil {
		return err
	}

	return c.searchCli.WriteIndex(context.TODO(), sserver1.WriteIndexArg{SecureIndex: secIndexBytes, DocID: docID})
}

// RenameFile is called when a file has been renamed from `orig` to `curr`.
// This will rename their corresponding indexes.  Returns an error if the
// filenames are invalid.
func (c *Client) RenameFile(orig, curr string) error {
	return nil
}
