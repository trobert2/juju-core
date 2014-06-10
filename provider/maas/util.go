// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package maas

import (
	"fmt"
	"net/url"
	"strings"
	"path"

	"launchpad.net/goyaml"

	"launchpad.net/juju-core/environs"
	"launchpad.net/juju-core/instance"
	"launchpad.net/juju-core/utils"
	"launchpad.net/juju-core/juju/osenv"
)

// extractSystemId extracts the 'system_id' part from an InstanceId.
// "/MAAS/api/1.0/nodes/system_id/" => "system_id"
func extractSystemId(instanceId instance.Id) string {
	trimmed := strings.TrimRight(string(instanceId), "/")
	split := strings.Split(trimmed, "/")
	return split[len(split)-1]
}

// getSystemIdValues returns a url.Values object with all the 'system_ids'
// from the given instanceIds stored under the specified key.  This is used
// to filter out instances when listing the nodes objects.
func getSystemIdValues(key string, instanceIds []instance.Id) url.Values {
	values := url.Values{}
	for _, instanceId := range instanceIds {
		values.Add(key, extractSystemId(instanceId))
	}
	return values
}

// machineInfo is the structure used to pass information between the provider
// and the agent running on a node.
// When a node is started, the provider code creates a machineInfo object
// containing information about the node being started and configures
// cloudinit to get a YAML representation of that object written on the node's
// filesystem during its first startup.  That file is then read by the juju
// agent running on the node and converted back into a machineInfo object.
type machineInfo struct {
	Hostname string `yaml:,omitempty`
}

var _MAASInstanceFilename = path.Join(environs.DataDir, "MAASmachine.txt")

// cloudinitRunCmd returns the shell command that, when run, will create the
// "machine info" file containing the hostname of a machine.
// That command is destined to be used by cloudinit.
func (info *machineInfo) cloudinitRunCmd() (string, error) {
	yaml, err := goyaml.Marshal(info)
	if err != nil {
		return "", err
	}
	script := fmt.Sprintf(`mkdir -p %s; echo -n %s > %s`, utils.ShQuote(environs.DataDir), utils.ShQuote(string(yaml)), utils.ShQuote(_MAASInstanceFilename))
	return script, nil
}

// load loads the "machine info" file and parse the content into the info
// object.
func (info *machineInfo) load() error {
	return utils.ReadYaml(_MAASInstanceFilename, info)
}

// winCloudinitRunCmd returns the shell command that, when run, will create the
// "machine info" file containing the hostname of a machine on a winows system.
// That command is destined to be used by cloudinit.
func (info *machineInfo) winCloudinitRunCmd() (string, error) {
	_MAASInstanceFilenameWin := path.Join(osenv.WinDataDir, "MAASmachine.txt")
	yaml, err := goyaml.Marshal(info)
	if err != nil {
		return "", err
	}
	script := fmt.Sprintf("mkdir \"%s\"\r\n Set-Content \"%s\" @\"\n%s\n\"@", utils.PathToWindows(osenv.WinDataDir), utils.PathToWindows(_MAASInstanceFilenameWin), string(yaml))
	return script, nil
}
