#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
}

# TODO:
# - Test other actions like SCMP_ACT_TRAP, SCMP_ACT_TRACE, SCMP_ACT_LOG.
# - Test args (index, value, valueTwo, etc).

@test "runc run [seccomp] (SCMP_ACT_ERRNO default)" {
	update_config '.process.args = ["/bin/sh", "-c", "mkdir /dev/shm/foo"] |
		.process.noNewPrivileges = false |
		.linux.seccomp = {
			"defaultAction":"SCMP_ACT_ALLOW",
			"architectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"],
			"syscalls":[{"names":["mkdir"], "action":"SCMP_ACT_ERRNO"}]
		}'

	runc run test_busybox
	[ "$status" -ne 0 ]
	[[ "$output" == *"Operation not permitted"* ]]
}

@test "runc run [seccomp] (SCMP_ACT_ERRNO explicit errno)" {
	update_config '.process.args = ["/bin/sh", "-c", "mkdir /dev/shm/foo"] |
		.process.noNewPrivileges = false |
		.linux.seccomp = {
			"defaultAction":"SCMP_ACT_ALLOW",
			"architectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"],
			"syscalls":[{"names":["mkdir"], "action":"SCMP_ACT_ERRNO", "errnoRet": 100}]
		}'

	runc run test_busybox
	[ "$status" -ne 0 ]
	[[ "$output" == *"Network is down"* ]]
}

@test "runc run [seccomp] (SCMP_ACT_KILL)" {
	update_config '.process.args = ["/bin/sh", "-c", "mkdir /dev/shm/foo"] |
		.process.noNewPrivileges = false |
		.linux.seccomp = {
			"defaultAction":"SCMP_ACT_ALLOW",
			"architectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"],
			"syscalls":[{"names":["mkdir"], "action":"SCMP_ACT_KILL"}]
		}'

	runc run test_busybox
	[ "$status" -ne 0 ]
}

# check that a startContainer hook is run with the seccomp filters applied
@test "runc run [seccomp] (startContainer hook)" {
	update_config '.process.args = ["/bin/true"] |
		.linux.seccomp = {
			"defaultAction":"SCMP_ACT_ALLOW",
			"architectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"],
			"syscalls":[{"names":["mkdir"], "action":"SCMP_ACT_KILL"}]
		} |
		.hooks = {
			"startContainer": [
				{
					"path": "/bin/sh",
					"args": ["sh", "-c", "mkdir /dev/shm/foo"]
				}
			]
		}'

	runc run test_busybox
	[ "$status" -ne 0 ]
	[[ "$output" == *"error running hook"* ]]
	[[ "$output" == *"bad system call"* ]]
}
