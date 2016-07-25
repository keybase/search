# Keyword Search on KBFS Data

Supports keyword search on encrypted data stored in KBFS.

This is an early prototype simulating the whole process locally with clients and
a server. The network traffic is simulated by applying latency and bandwidth to
the time logging.

To run the demo, simply do:

```
go run main.go
```

Or better, with time logging:

```
go run main.go --enable_logger
```

The clients have a default storage directory of `.client_fs/` and the server has
a default directory of `.server_fs/`.  Use `go run main.go --help` to see other
configurable parameters.

A list of commands currently supported:
```
	client/c X
			Starts running client with client number X
	ls/l
			Lists all the files on the server
	search/s w1 w2 w3 ...
			Searches the words in the server
	add/a f1 f2 d1 d2 ...
			Adds the files and directories (recursive) to the system
	info/i
			Prints the server information
	exit/q
			Exits the program
```
