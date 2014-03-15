// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package osenv

import (
	"os"
	"path"
	"path/filepath"
)

var (
	TempDir    = WinTempDir
    LibDir     = WinLibDir
    LogDir     = WinLogDir
    DataDir    = WinDataDir
    JujuRun    = path.Join(WinBinDir, "juju-run.exe")
    SocketType = "tcp"
)

// Home returns the os-specific home path as specified in the environment
func Home() string {
	return path.Join(os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH"))
}

// SetHome sets the os-specific home path in the environment
func SetHome(s string) error {
	v := filepath.VolumeName(s)
	if v != "" {
		if err := os.Setenv("HOMEDRIVE", v); err != nil {
			return err
		}
	}
	return os.Setenv("HOMEPATH", s[len(v):])
}
