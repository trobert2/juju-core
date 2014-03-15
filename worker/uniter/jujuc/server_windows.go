package jujuc

import (
	"launchpad.net/juju-core/cmd"
)

// newCommands maps Command names to initializers.

// gsamfira: Windows cares about extensions
// Also, in windows you may omit the extension and the program
// will still run. Adding both variants
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
	"close-port":			NewClosePortCommand,
	"config-get":			NewConfigGetCommand,
	"juju-log":				NewJujuLogCommand,
	"open-port":			NewOpenPortCommand,
	"relation-get":			NewRelationGetCommand,
	"relation-ids":			NewRelationIdsCommand,
	"relation-list":		NewRelationListCommand,
	"relation-set":			NewRelationSetCommand,
	"unit-get":				NewUnitGetCommand,
	"owner-get":			NewOwnerGetCommand,
}