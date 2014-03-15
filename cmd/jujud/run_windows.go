// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
    "fmt"
    "net/rpc"
    "os"
    "path"
    "path/filepath"

    "launchpad.net/gnuflag"

    "launchpad.net/juju-core/cmd"
    "launchpad.net/juju-core/names"
    "launchpad.net/juju/osenv"
    "launchpad.net/juju-core/utils"
    "launchpad.net/juju-core/utils/exec"
    "launchpad.net/juju-core/utils/fslock"
    "launchpad.net/juju-core/worker/uniter"
)


const runCommandDoc = `
Run the specified commands in the hook context for the unit.

unit-name can be either the unit tag:
 i.e.  unit-ubuntu-0
or the unit id:
 i.e.  ubuntu/0

If --no-context is specified, the <unit-name> positional
argument is not needed.

The commands are executed with '/bin/bash -s', and the output returned.
`


func (c *RunCommand) executeInUnitContext() (*exec.ExecResponse, error) {
    unitDir := filepath.Join(AgentDir, c.unit)
    logger.Debugf("looking for unit dir %s", unitDir)
    // make sure the unit exists
    _, err := os.Stat(unitDir)
    if os.IsNotExist(err) {
        return nil, fmt.Errorf("unit %q not found on this machine", c.unit)
    } else if err != nil {
        return nil, err
    }

    socketPath := filepath.Join(unitDir, uniter.RunListenerFile)
    sock := utils.ReadSocketFile(socketPath)
    // make sure the socket exists
    client, err := rpc.Dial(osenv.SocketType, sock)
    if err != nil {
        return nil, err
    }
    defer client.Close()

    var result exec.ExecResponse
    err = client.Call(uniter.JujuRunEndpoint, c.commands, &result)
    return &result, err
}

func (c *RunCommand) executeNoContext() (*exec.ExecResponse, error) {
    // Acquire the uniter hook execution lock to make sure we don't
    // stomp on each other.
    lock, err := getLock()
    if err != nil {
        return nil, err
    }
    err = lock.Lock("juju-run")
    if err != nil {
        return nil, err
    }
    defer lock.Unlock()

    runCmd := `[ -f "/home/ubuntu/.juju-proxy" ] && . "/home/ubuntu/.juju-proxy"` + "\n" + c.commands

    return exec.RunCommands(
        exec.RunParams{
            Commands: runCmd,
        })
}
