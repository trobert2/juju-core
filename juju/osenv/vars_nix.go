// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.
// +build !windows

package osenv

import (
	"os"
	"path"
)

// Home returns the os-specific home path as specified in the environment
func Home() string {
	return os.Getenv("HOME")
}

// SetHome sets the os-specific home path in the environment
func SetHome(s string) error {
	return os.Setenv("HOME", s)
}

var (
	TempDir    = "/tmp"
	LibDir     = "/var/lib"
	LogDir     = "/var/log"
	DataDir    = path.Join(LibDir, "juju")
	JujuRun    = "/usr/local/bin/juju-run"
	SocketType = "unix"
	MustReboot = 101
)
