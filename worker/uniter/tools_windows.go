package uniter

import (
	"os"
	"path/filepath"

	"launchpad.net/juju-core/utils"
	"launchpad.net/juju-core/worker/uniter/jujuc"
)

// EnsureJujucSymlinks creates a symbolic link to jujuc within dir for each
// hook command. If the commands already exist, this operation does nothing.
func EnsureJujucSymlinks(dir string) (err error) {
	for _, name := range jujuc.CommandNames() {
		file := filepath.Join(dir, name)
		if _, err := os.Stat(file); err == nil {
			continue
		}
		jujudExe := filepath.Join(dir, "jujud.exe")
		err := utils.Symlink(jujudExe, filepath.FromSlash(file))
		if err == nil {
			continue
		}
		return err
	}
	return nil
}
