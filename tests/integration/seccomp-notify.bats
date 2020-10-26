#!/usr/bin/env bats

load helpers

function setup() {
	teardown_seccompagent
	setup_seccompagent

	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_seccompagent
	teardown_busybox
}

@test "runc run (seccomp notify tests)" {
	requires root
	requires no_systemd

	if [ "$KERNEL_MAJOR" -lt 5 ]; then
		skip "requires kernel 5.6"
	elif [ "$KERNEL_MINOR" -lt 6 ]; then
		skip "requires kernel 5.6"
	fi

	# The agent intercepts mkdir syscalls and creates the folder appending
	# "-foo" to the name.
	update_config	'.hooks |= . + {"sendSeccompFd": [{"path": "'"${SECCOMPHOOK}"'", "args": []}]} |
		.process.args = ["/bin/sh", "-c", "mkdir /dev/shm/foo && stat /dev/shm/foo-boo"] |
		.linux.seccomp = {"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["mkdir"],"action":"SCMP_ACT_NOTIFY"}]}'

	runc run test_busybox
	[ "$status" -eq 0 ]
}
