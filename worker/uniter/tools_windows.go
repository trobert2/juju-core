// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package uniter

import (
    "fmt"
    "os"
    "path/filepath"

    "launchpad.net/juju-core/worker/uniter/jujuc"
    "launchpad.net/juju-core/utils"
)

// EnsureJujucSymlinks creates a symbolic link to jujuc within dir for each
// hook command. If the commands already exist, this operation does nothing.

func EnsureJujucSymlinks(dir string) (err error) {
    for _, name := range jujuc.CommandNames() {
        // We only need to create symlinks to the .exe variants
        ext := name[len(name)-4:]
        if ext != ".exe"{
            continue
        }
        file := filepath.Join(dir, name)
        if _, err := os.Stat(file); err != nil {
            err = os.Remove(file)
            if err != nil {
                return errors.New(fmt.Sprintf("Failed to remove old symlink: %s", file))
            }
        }
        err := utils.CreateSymLink(filepath.FromSlash(file), "jujud.exe")
        if err == nil {
            continue
        }
        return err
    }
    return nil
}
