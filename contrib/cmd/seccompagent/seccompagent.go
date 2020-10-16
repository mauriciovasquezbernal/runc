// +build linux,cgo,seccomp
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

/*
#include <stdio.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>

struct _mydef_seccomp_notif_addfd {
  __u64 id;
  __u32 flags;
  __u32 srcfd;
  __u32 newfd;
  __u32 newfd_flags;
};

#define SECCOMP_IOC_MAGIC		'!'
#define SECCOMP_IO(nr)			_IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type)	_IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type)	_IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type)	_IOWR(SECCOMP_IOC_MAGIC, nr, type)

#ifndef SECCOMP_ADDFD_FLAG_SETFD
#define SECCOMP_ADDFD_FLAG_SETFD (1UL << 0)
#endif

#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
#define SECCOMP_IOCTL_NOTIF_ADDFD                                              \
  SECCOMP_IOW(3, struct _mydef_seccomp_notif_addfd)
#endif

int replace_fd(__u64 id, int notify_fd, int fd) {
	struct _mydef_seccomp_notif_addfd addfd = {
		.id = id,
		.flags = 0,
		.srcfd = fd,
		.newfd = 0,
		.newfd_flags = 0,
	};
	return ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
}
*/
import "C"

var (
	socketFile string
)

func init() {
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
}

const (
	fileNameContainer = "/dev/null2"
	fileNameHost      = "/tmp/devnull2"
)

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
	fmt.Printf("%v\n", ociState)

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

func readArgString(pid uint32, offset int64) (string, error) {
	var buffer = make([]byte, 4096) // PATH_MAX

	memfd, err := syscall.Open(fmt.Sprintf("/proc/%d/mem", pid), syscall.O_RDONLY, 0777)
	if err != nil {
		return "", err
	}
	defer syscall.Close(memfd)

	_, err = syscall.Pread(memfd, buffer, offset)
	if err != nil {
		return "", err
	}

	buffer[len(buffer)-1] = 0
	s := buffer[:bytes.IndexByte(buffer, 0)]
	return string(s), nil
}

func runOpenForContainer(fileName string, fd int,
	req *libseccomp.ScmpNotifReq, resp *libseccomp.ScmpNotifResp) {
	if fileName != fileNameContainer {
		return
	}

	fileFd, err := syscall.Open(fileNameHost, 0, 0)
	if err != nil {
		fmt.Println("Failed to open file at host")
		return
	}
	defer syscall.Close(fileFd)

	ret := C.replace_fd(C.ulonglong(req.ID), C.int(fd), C.int(fileFd))
	if ret < 0 {
		fmt.Println("Error replacing fd on target")
		return
	}
	resp.Flags = 0
	resp.Val = uint64(ret)

	fmt.Printf("Injected fd %d into target process for %q\n", ret, fileNameHost)
}

// notifHandler handles seccomp notifications and responses
func notifHandler(fd libseccomp.ScmpFd) {
	defer syscall.Close(int(fd))
	for {
		req, err := libseccomp.NotifReceive(fd)
		if err != nil {
			if err == syscall.ECANCELED {
				continue
			}
			fmt.Printf("Error in NotifReceive(): %s", err)
			return
		}
		syscallName, err := req.Data.Syscall.GetName()
		if err != nil {
			fmt.Printf("Error in decoding syscall %v(): %s", req.Data.Syscall, err)
			continue
		}

		// TOCTOU check
		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			fmt.Printf("TOCTOU check failed: req.ID is no longer valid: %s", err)
			continue
		}

		resp := &libseccomp.ScmpNotifResp{
			ID:    req.ID,
			Error: 0,
			Val:   0,
			Flags: libseccomp.NotifRespFlagContinue,
		}

		switch syscallName {
		case "openat":
			fileName, err := readArgString(req.Pid, int64(req.Data.Args[1]))
			if err != nil {
				fmt.Printf("Cannot read argument: %s", err)
				goto notify
			}
			runOpenForContainer(fileName, int(fd), req, resp)
		case "open":
			fileName, err := readArgString(req.Pid, int64(req.Data.Args[0]))
			if err != nil {
				fmt.Printf("Cannot read argument: %s", err)
				goto notify
			}
			runOpenForContainer(fileName, int(fd), req, resp)
		}

	notify:
		if err = libseccomp.NotifRespond(fd, resp); err != nil {
			fmt.Printf("Error in notification response: %s", err)
		}
	}
}

func main() {
	// Parse arguments
	flag.Parse()
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(errors.New("invalid command"))
	}

	if err := os.RemoveAll(socketFile); err != nil {
		panic(err)
	}

	l, err := net.Listen("unix", socketFile)
	if err != nil {
		panic(fmt.Errorf("cannot listen on %s: %s", socketFile, err))
	}
	defer l.Close()

	fmt.Println("Waiting for seccomp fds")

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
		go notifHandler(libseccomp.ScmpFd(newFd.Fd()))
	}

}
