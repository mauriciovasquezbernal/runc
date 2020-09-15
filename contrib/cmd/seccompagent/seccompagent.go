package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

/*
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

// Flags for seccomp notification fd ioctl.
// Taken from https://elixir.bootlin.com/linux/v5.9-rc3/source/tools/testing/selftests/seccomp/seccomp_bpf.c#L3958

#define SECCOMP_IOC_MAGIC		'!'
#define SECCOMP_IOWR(nr, type)		_IOWR(SECCOMP_IOC_MAGIC, nr, type)

#define SECCOMP_IOCTL_NOTIF_RECV	SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND	SECCOMP_IOWR(1,	\
						struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID	SECCOMP_IOW(2, uint64_t)

struct seccomp_data {
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};

struct seccomp_metadata {
	uint64_t filter_off;       // Input: which filter
	uint64_t flags;             // Output: filter's flags
};

struct seccomp_notif {
	uint64_t id;
	uint32_t pid;
	uint32_t flags;
	struct seccomp_data data;
};

struct seccomp_notif_resp {
	uint64_t id;
	int64_t val;
	int32_t error;
	uint32_t flags;
};

static int handle_syscall(int notify_fd, int64_t resp_val)
{
	struct seccomp_notif req = {};
	struct seccomp_notif_resp resp = {};
	int ret;

	memset(&req, 0, sizeof(req));
	ret = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req);
	if (ret != 0)
		return ret;

	printf("Received event on seccomp fd %d: id=%llu pid=%d flags=%d nr=%d arch=%u instruction_pointer=%llu args=[%llx %llx %llx %llx %llx %llx]\n",
		notify_fd, req.id, req.pid, req.flags,
		req.data.nr, req.data.arch, req.data.instruction_pointer,
		req.data.args[0], req.data.args[1], req.data.args[2],
		req.data.args[3], req.data.args[4], req.data.args[5]);

	memset(&resp, 0, sizeof(resp));
	resp.id = req.id;
	resp.error = 0;
	resp.val = resp_val;
	ret = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
	if (ret != 0)
		return ret;

	return 0;
}
*/
import "C"

var (
	socketFile string
)

func init() {
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
}

func handleNewMessage(sockfd int) (*os.File, error) {
	MaxNameLen := 4096
	oobSpace := unix.CmsgSpace(4)
	stateBuf := make([]byte, 4096)
	oob := make([]byte, oobSpace)

	n, oobn, _, _, err := unix.Recvmsg(sockfd, stateBuf, oob, 0)
	if err != nil {
		return nil, err
	}
	if n >= MaxNameLen || oobn != oobSpace {
		return nil, fmt.Errorf("recvfd: incorrect number of bytes read (n=%d oobn=%d)", n, oobn)
	}

	// Truncate.
	stateBuf = stateBuf[:n]
	oob = oob[:oobn]

	ociState := &specs.State{}
	err = json.Unmarshal(stateBuf, ociState)
	if err != nil {
		return nil, fmt.Errorf("cannot parse OCI state: %v\n", err)
	}

	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	if len(scms) != 1 {
		return nil, fmt.Errorf("recvfd: number of SCMs is not 1: %d", len(scms))
	}
	scm := scms[0]

	fds, err := unix.ParseUnixRights(&scm)
	if err != nil {
		return nil, err
	}
	if len(fds) != 1 {
		return nil, fmt.Errorf("recvfd: number of fds is not 1: %d", len(fds))
	}
	fd := uintptr(fds[0])

	return os.NewFile(fd, "seccomp-fd"), nil
}

func main() {
	// Parse arguments
	flag.Parse()
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(fmt.Errorf("invalid command"))
	}

	if err := os.RemoveAll(socketFile); err != nil {
		panic(err)
	}

	l, err := net.Listen("unix", socketFile)
	if err != nil {
		panic(fmt.Errorf("cannot listen on %s:", socketFile, err))
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			panic(fmt.Errorf("cannot accept connection: %s", err))
		}
		socket, err := conn.(*net.UnixConn).File()
		conn.Close()
		if err != nil {
			panic(fmt.Errorf("cannot get socket: %v\n", err))
		}

		newFd, err := handleNewMessage(int(socket.Fd()))
		if err != nil {
			fmt.Printf("%s\n", err)
		}
		socket.Close()

		fmt.Printf("Received new seccomp fd: %v\n", newFd.Fd())

		go func() {
			for {
				ret := C.handle_syscall(C.int(newFd.Fd()), C.int64_t(-42))
				if ret != 0 {
					fmt.Printf("Closing seccomp fd %d\n", newFd.Fd())
					newFd.Close()
					return
				}
			}
		}()
	}

}
