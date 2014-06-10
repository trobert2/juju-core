package osenv

import (
	"path"
)

var (
	TempDir    = WinTempDir
	LibDir     = WinLibDir
	LogDir     = WinLogDir
	DataDir    = WinDataDir
	JujuRun    = path.Join(WinBinDir, "juju-run.exe")
	SocketType = "tcp"
	MustReboot = 1001
)
