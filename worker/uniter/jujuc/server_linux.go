package jujuc

import (
    "launchpad.net/juju-core/cmd"
)

// newCommands maps Command names to initializers.
var newCommands = map[string]func(Context) cmd.Command{
	"close-port":    NewClosePortCommand,
	"config-get":    NewConfigGetCommand,
	"juju-log":      NewJujuLogCommand,
	"open-port":     NewOpenPortCommand,
	"relation-get":  NewRelationGetCommand,
	"relation-ids":  NewRelationIdsCommand,
	"relation-list": NewRelationListCommand,
	"relation-set":  NewRelationSetCommand,
	"unit-get":      NewUnitGetCommand,
	"owner-get":     NewOwnerGetCommand,
}
