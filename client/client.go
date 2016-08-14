package client

import (
	"crypto/sha256"
	"fmt"
	"net"

	rpc "github.com/keybase/go-framed-msgpack-rpc"
	"github.com/keybase/search/libsearch"
	sserver1 "github.com/keybase/search/protocol/sserver"
	"golang.org/x/net/context"
)

type Client struct {
	searchCli sserver1.SearchServerClient
	directory string
	indexer   *libsearch.SecureIndexBuilder
}

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

	cli := new(Client)
	*cli = Client{
		searchCli: searchCli,
		directory: directory,
		indexer:   indexer,
	}

	return cli, nil
}
