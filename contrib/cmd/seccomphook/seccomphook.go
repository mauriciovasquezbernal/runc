// +build linux,cgo,seccomp

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/opencontainers/runc/libcontainer/utils"

	"github.com/opencontainers/runtime-spec/specs-go"
)

var (
	socketFile string
)

func init() {
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
}

func main() {
	// Parse arguments
	flag.Parse()
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(errors.New("invalid command"))
	}

	// Parse state from stdin
	stateBuf, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Errorf("cannot read stdin: %v\n", err))
	}

	seccompState := &specs.SeccompState{}
	err = json.Unmarshal(stateBuf, seccompState)
	if err != nil {
		panic(fmt.Errorf("cannot parse OCI state: %v\n", err))
	}

	conn, err := net.Dial("unix", socketFile)
	if err != nil {
		panic(fmt.Errorf("cannot connect to %s: %v\n", socketFile, err))
	}

	/* Thanks Go! */
	socket, err := conn.(*net.UnixConn).File()
	if err != nil {
		panic(fmt.Errorf("cannot get socket: %v\n", err))
	}
	defer socket.Close()

	// Send fd to agent using SCM_RIGHTS
	err = utils.SendFd(socket, string(stateBuf), uintptr(seccompState.SeccompFd))
	if err != nil {
		panic(fmt.Errorf("cannot send seccomp fd to %s: %v\n", socketFile, err))
	}
}
