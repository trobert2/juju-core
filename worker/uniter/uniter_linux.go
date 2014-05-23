package uniter

import (
    //"math/rand"
    //"os"
    "path/filepath"
    //"time"
    "fmt"

    "launchpad.net/juju-core/cmd"
    "launchpad.net/juju-core/worker/uniter/jujuc"
)

func (u *Uniter) startJujucServer(context *HookContext) (*jujuc.Server, string, error) {
	// Prepare server.
	getCmd := func(ctxId, cmdName string) (cmd.Command, error) {
		// TODO: switch to long-running server with single context;
		// use nonce in place of context id.
		if ctxId != context.id {
			return nil, fmt.Errorf("expected context id %q, got %q", context.id, ctxId)
		}
		return jujuc.NewCommand(context, cmdName)
	}
	socketPath := filepath.Join(u.baseDir, "agent.socket")
	// Use abstract namespace so we don't get stale socket files.
	socketPath = "@" + socketPath
	srv, err := jujuc.NewServer(getCmd, socketPath)
	if err != nil {
		return nil, "", err
	}
	go srv.Run()
	return srv, socketPath, nil
}
