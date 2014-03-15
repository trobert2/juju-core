// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
    "fmt"
    "net/rpc"
    "os"
    "path/filepath"

    "launchpad.net/juju-core/juju/osenv"
    "launchpad.net/juju-core/utils/exec"
    "launchpad.net/juju-core/worker/uniter"
)


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
    // make sure the socket exists
    client, err := rpc.Dial(osenv.SocketType, socketPath)
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