package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

var serverMountPoint = flag.String("server_mp", "server_fs", "the mount point for the server where all the server side data is stored")

func main() {
	reader := bufio.NewReader(os.Stdin)
	flag.Parse()
	fmt.Printf("Running with server mounted at %s/\n", *serverMountPoint)
	for {
		fmt.Print("> ")
		cmd, _ := reader.ReadString('\n')
		cmd = cmd[:len(cmd)-1]
		tokens := strings.Split(cmd, " ")
		switch tokens[0] {
		case "exit":
			fmt.Println("Program exited.")
			return
		case "":
			continue
		}
		fmt.Printf("%s: command not found\n", tokens[0])
	}
}
