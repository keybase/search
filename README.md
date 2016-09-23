# Keybase Filesystem (KBFS) Keyword Search

This repository contains a preliminary implementation of the client-side code
for the Keybase Filesystem (KBFS) Keyword Search.  See the
[wiki](https://github.com/keybase/search/wiki) for a brief
introduction and overview.

All code is written in the [Go Language](https://golang.org), and relies
on [KBFS](https://github.com/keybase/kbfs/tree/master/go).

### Architecture

This client allows keyword searching for files stored in KBFS.  It relies on
KBFS for syncing the master secrets and communicates remotely with the search
server to update the indexes stored on the server and perform keyword searches.

The code is organized as follows:

* [client](client/): The client-side code for the search scheme.
* [genprotocol](genprotocol/): Contains the AVDL files defining client-server RPC communication. If you need to make protocol changes, edit the files in this directory.
* [libsearch](libsearch/): Our implementation of the [secure index](http://eprint.iacr.org/2003/216.pdf) and other helper functions.
* [protocol](protocol/): Contains auto-generated code derived from the protocol definitions in `genprotocol/`.  Should not be edited by hand.
* [prototype](prototype/): An early-stage prototype the implements the search scheme locally.
* [vendor](vendor/): Vendored versions of the open-source libraries used by KBFS search.

### Running the Client
Once the search server is up and running at `SERVER_ADDRESS:SERVER_PORT`, to start the client and enable searches in specific `KBFS_DIRECTORIES_TO_SEARCH` (separated by semicolons):
```
cd client/client
go run main.go --client_dirs=KBFS_DIRECTORIES_TO_SEARCH --ip_addr=SERVER_ADDRESS --port=SERVER_PORT
```
Use `go run main.go --help` to see other configurable parameters.

### Licensing
Most code is released under the New BSD (3 Clause) License.  If subdirectories include a different license, that license applies instead.  (Specifically, most subdirectories in [vendor](vendor/) are released under their own licenses.)
