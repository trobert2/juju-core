package jujuc

import (
	"launchpad.net/juju-core/cmd"
)

// newCommands maps Command names to initializers.

// gsamfira: Windows cares about extensions
var newCommands = map[string]func(Context) cmd.Command{
	"close-port.exe":		NewClosePortCommand,
	"config-get.exe":		NewConfigGetCommand,
	"juju-log.exe":			NewJujuLogCommand,
	"open-port.exe":		NewOpenPortCommand,
	"relation-get.exe":		NewRelationGetCommand,
	"relation-ids.exe":		NewRelationIdsCommand,
	"relation-list.exe":	NewRelationListCommand,
	"relation-set.exe":		NewRelationSetCommand,
	"unit-get.exe":			NewUnitGetCommand,
	"owner-get.exe":		NewOwnerGetCommand,
}