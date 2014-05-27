package uniter

import (
	"fmt"

	"launchpad.net/juju-core/cmd"
	"launchpad.net/juju-core/utils"
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
	// gsamfira: This function simply returns a free TCP socket.
	// TODO: Must see if this socket is used by any other process then charms
	socketPath, errSock := utils.GetSocket()
	if errSock != nil {
		return nil, "", errSock
	}
	srv, err := jujuc.NewServer(getCmd, socketPath)
	if err != nil {
		return nil, "", err
	}
	go srv.Run()
	return srv, socketPath, nil
}
