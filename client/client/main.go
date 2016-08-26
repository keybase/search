package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/keybase/search/client"
	"golang.org/x/net/context"
)

var clientDirectory = flag.String("client_dir", "/keybase/private/jiaxin", "the keybase directory for the client where the files should be indexed")
var port = flag.Int("port", 8022, "the port that the search server is listening on")
var ipAddr = flag.String("ip_addr", "127.0.0.1", "the IP address that the search server is listening on")

// periodicAdd scans the files in the client directory every minute and adds
// their indexes to the search server.
func periodicAdd(cli *client.Client) {
	for {
		files, _ := ioutil.ReadDir(*clientDirectory)
		for _, file := range files {
			cli.AddFile(filepath.Join(*clientDirectory, file.Name()))
			fmt.Println("Added:", filepath.Join(*clientDirectory, file.Name()))
		}
		fmt.Println("Files Added")
		time.Sleep(time.Second * 60)
	}
}

func main() {
	flag.Parse()

	cli, err := client.CreateClient(context.TODO(), *ipAddr, *port, []byte("A really really really long Master Secret, oh god it's so long"), *clientDirectory)
	if err != nil {
		fmt.Printf("Cannot initiate the client: %s\n", err)
		os.Exit(1)
	}
	go periodicAdd(cli)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Please enter word to search for: ")
		keyword, _ := reader.ReadString('\n')
		keyword = keyword[:len(keyword)-1]
		files, err := cli.SearchWord(keyword)
		if err != nil {
			fmt.Printf("Error when searching word %s: %s", keyword, err)
			continue
		}
		fmt.Println(files)
	}

}
