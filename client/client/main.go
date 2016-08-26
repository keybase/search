package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	//"time"

	"github.com/keybase/search/client"
	"golang.org/x/net/context"
)

var clientDirectory = flag.String("client_dir", "/keybase/private", "the keybase directory for the client where the files should be indexed")
var port = flag.Int("port", 8022, "the port that the search server is listening on")
var ipAddr = flag.String("ip_addr", "127.0.0.1", "the IP address that the search server is listening on")

func periodicAdd(cli *client.Client) {
	//for {
	files, _ := ioutil.ReadDir(*clientDirectory)
	for _, file := range files {
		cli.AddFile(filepath.Join(*clientDirectory, file.Name()))
	}
	//		time.Sleep(60)
	//	}
}

func main() {
	flag.Parse()

	cli, err := client.CreateClient(context.TODO(), *ipAddr, *port, []byte("A really really really long Master Secret, oh god it's so long"), *clientDirectory)
	if err != nil {
		fmt.Println("Cannot initiate the client: %s", err)
		os.Exit(1)
	}
	periodicAdd(cli)

}
