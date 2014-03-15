package main

import (
    "os"
    "path/filepath"
)

func (a *MachineAgent) initAgent() error {
    if err := os.Remove(jujuRun); err != nil && !os.IsNotExist(err) {
        return err
    }
    jujud := filepath.Join(a.Conf.dataDir, "tools", a.Tag(), "jujud")
    return os.Symlink(jujud, jujuRun)
}