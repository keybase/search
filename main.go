package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path"
	"search/client"
	"search/server"
	"strconv"
	"strings"
)

// Sets up the server-side flags
var numClients = flag.Int("num_clients", 5, "the number of clients for the server")
var lenMS = flag.Int("len_ms", 8, "the length of the master secret")
var lenSalt = flag.Int("len_salt", 8, "the length of the salts used to generate the PRFs")
var fpRate = flag.Float64("fp_rate", 0.000001, "the desired false positive rate for searchable encryption")
var numUniqWords = flag.Uint64("num_words", uint64(10000), "the expected number of unique words in all the documents")
var serverMountPoint = flag.String("server_mp", "server_fs", "the mount point for the server where all the server side data is stored")

// Sets up the client-side flags
var defaultClientNum = flag.Int("default_client_num", 0, "the dafault running client (set to -1 to initialize without a client)")
var clientMountPoint = flag.String("client_mp", "client_fs", "the mount point for the client where the client stores all the data")

// startServer initializes the server for the program.  It either creates a new
// one or loads from the server metadata at the mount point.
func startServer() *server.Server {
	if _, err := os.Stat(path.Join(*serverMountPoint, "serverMD")); err == nil {
		fmt.Println("Server metadata found, loading server from mount point", *serverMountPoint)
		return server.LoadServer(*serverMountPoint)
	}
	if _, err := os.Stat(*serverMountPoint); os.IsNotExist(err) {
		if os.Mkdir(*serverMountPoint, 0777) != nil {
			fmt.Println("Failed to create the server mount point", *serverMountPoint)
		}
	}
	fmt.Println("No previous server metadata found, starting new server at mount point", *serverMountPoint)
	return server.CreateServer(*numClients, *lenMS, *lenSalt, *serverMountPoint, *fpRate, *numUniqWords)
}

// startClient initializes a client with `clientNum` connected to `server`.
func startClient(server *server.Server, clientNum int) *client.Client {
	if clientNum == -1 {
		fmt.Println("No client running")
		return nil
	}
	fmt.Println("Now running client", clientNum)
	return client.CreateClient(server, clientNum, path.Join(*clientMountPoint, "client"+strconv.Itoa(clientNum)))
}

// addFile adds `file` to `client` if `file` exists and has not already been
// added.
func addFile(client *client.Client, file string) {
	_, filename := path.Split(file)
	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Printf("Cannot add file %s: file does not exist\n", filename)
		return
	}
	success := client.AddFile(file)
	if success {
		fmt.Printf("File %s successfully added\n", filename)
	} else {
		fmt.Printf("Cannot add file %s: file already added\n", filename)
	}
}

// A list of commands:
//	-client/c X
//			Starts running client with client number X
//	-ls/l
//			Lists all the files on the server
//	-search/s w1 w2 w3 ...
//			Searches the words in the server
//	-add/a f1 f2 f3 ...
//			Adds the files to the system
//	-info/i
//			Prints the server information
//	-exit/q
//			Exits the program
func main() {
	flag.Parse()

	// Initialize the server
	server := startServer()
	fmt.Printf("\nServer Started\n--------------\n")
	server.PrintServerInfo()
	fmt.Println()

	// Initialize the client
	if _, err := os.Stat(*clientMountPoint); os.IsNotExist(err) {
		if os.Mkdir(*clientMountPoint, 0777) != nil {
			fmt.Println("Failed to create the client mount point", *clientMountPoint)
		}
	}
	client := startClient(server, *defaultClientNum)
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		cmd, _ := reader.ReadString('\n')
		cmd = cmd[:len(cmd)-1]
		tokens := strings.Split(cmd, " ")
		switch tokens[0] {
		case "client", "c":
			if len(tokens) < 2 {
				fmt.Printf("%s: client number missing\n", tokens[0])
				break
			}
			clientNum, err := strconv.Atoi(tokens[1])
			if err != nil || clientNum < 0 || clientNum >= server.GetNumClients() {
				fmt.Printf("%s: invalid client number \"%s\"\n", tokens[0], tokens[1])
				break
			}
			client = startClient(server, clientNum)
		case "ls", "l":
			if client == nil {
				fmt.Printf("%s: client not running\n", tokens[0])
				break
			}
			for _, filename := range client.GetFilenames() {
				fmt.Println(filename)
			}
		case "search", "s":
			if client == nil {
				fmt.Printf("%s: client not running\n", tokens[0])
				break
			}
			if len(tokens) < 2 {
				fmt.Printf("%s: search keyword missing\n", tokens[0])
				break
			}
			for i := 1; i < len(tokens); i++ {
				fmt.Printf("Search result for %s:\n", tokens[i])
				filenames := client.SearchWord(tokens[i])
				if len(filenames) == 0 {
					fmt.Printf("\tNo file contains the word \"%s\"\n", tokens[i])
				}
				for _, filename := range filenames {
					fmt.Printf("\t%s\n", filename)
				}
			}
		case "add", "a":
			if client == nil {
				fmt.Printf("%s: client not running\n", tokens[0])
				break
			}
			if len(tokens) < 2 {
				fmt.Printf("%s: file name missing\n", tokens[0])
				break
			}
			for i := 1; i < len(tokens); i++ {
				addFile(client, tokens[i])
			}
		case "info", "i":
			server.PrintServerInfo()
		case "exit", "q":
			fmt.Println("Program exited.")
			return
		case "":
		default:
			fmt.Printf("%s: command not found\n", tokens[0])
		}
	}
}
