package tools

import (
    "fmt"
    "os"

    coretools "launchpad.net/juju-core/tools"
    "launchpad.net/juju-core/version"
    "launchpad.net/juju-core/utils"
)


// ChangeAgentTools atomically replaces the agent-specific symlink
// under dataDir so it points to the previously unpacked
// version vers. It returns the new tools read.
func ChangeAgentTools(dataDir string, agentName string, vers version.Binary) (*coretools.Tools, error) {
    tools, err := ReadTools(dataDir, vers)
    if err != nil {
        return nil, err
    }
    tmpName := ToolsDir(dataDir, "tmplink-"+agentName)
    err = utils.Symlink(tools.Version.String(), tmpName)
    if err != nil {
        return nil, fmt.Errorf("cannot create tools symlink: %v", err)
    }
    err = os.Rename(tmpName, ToolsDir(dataDir, agentName))
    if err != nil {
        return nil, fmt.Errorf("cannot update tools symlink: %v", err)
    }
    return tools, nil
}
