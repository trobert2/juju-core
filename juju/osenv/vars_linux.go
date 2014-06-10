package osenv

import (
	"path"
)

var (
	TempDir    = "/tmp"
	LibDir     = "/var/lib"
	LogDir     = "/var/log"
	DataDir    = path.Join(LibDir, "juju")
	JujuRun    = "/usr/local/bin/juju-run"
	SocketType = "unix"
	MustReboot = 101
)
