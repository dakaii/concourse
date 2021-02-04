package spec

import "github.com/opencontainers/runtime-spec/specs-go"

var (
	// These rules are copied from runc. Good context here:
	// https://github.com/opencontainers/runc/blob/19437f3a55eb28411a4f48efdd494b1e3f49e055/libcontainer/specconv/spec_linux.go#L50-L64
	// Currently these rules are highly permissive.
	// We may want to re-visit them, especially the first two rules.
	// Linux docs about how cgroup device rules work:
	// https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/cgroup-v1/devices.rst
	AnyContainerDevices = []specs.LinuxDeviceCgroup{
		{Access: "m", Type: "c", Major: deviceWildcard(), Minor: deviceWildcard(), Allow: true},
		{Access: "m", Type: "b", Major: deviceWildcard(), Minor: deviceWildcard(), Allow: true},

		{Access: "rwm", Type: "c", Major: intRef(1), Minor: intRef(3), Allow: true},          // /dev/null
		{Access: "rwm", Type: "c", Major: intRef(1), Minor: intRef(8), Allow: true},          // /dev/random
		{Access: "rwm", Type: "c", Major: intRef(1), Minor: intRef(7), Allow: true},          // /dev/full
		{Access: "rwm", Type: "c", Major: intRef(5), Minor: intRef(0), Allow: true},          // /dev/tty
		{Access: "rwm", Type: "c", Major: intRef(1), Minor: intRef(5), Allow: true},          // /dev/zero
		{Access: "rwm", Type: "c", Major: intRef(1), Minor: intRef(9), Allow: true},          // /dev/urandom
		{Access: "rwm", Type: "c", Major: intRef(136), Minor: deviceWildcard(), Allow: true}, // /dev/pts/*
		{Access: "rwm", Type: "c", Major: intRef(5), Minor: intRef(2), Allow: true},          // /dev/ptmx
		{Access: "rwm", Type: "c", Major: intRef(10), Minor: intRef(200), Allow: true},       // /dev/net/tun
		{Access: "rwm", Type: "c", Major: intRef(10), Minor: intRef(229), Allow: true}, 	// /dev/fuse
	}
)

func intRef(i int64) *int64  { return &i }
func deviceWildcard() *int64 { return intRef(-1) }
