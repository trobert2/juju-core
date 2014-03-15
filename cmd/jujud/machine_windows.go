package main

import (
    "os"
    "path/filepath"

    "launchpad.net/juju-core/utils"
)

func (a *MachineAgent) initAgent() error {
    if err := os.Remove(jujuRun); err != nil && !os.IsNotExist(err) {
        return err
    }
    jujud := filepath.Join(a.Conf.dataDir, "tools", a.Tag(), "jujud.exe")
    return utils.CreateSymLink(jujuRun, jujud)
}