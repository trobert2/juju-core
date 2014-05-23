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
    logger.Infof("reading tools %q --> %q", dataDir, vers)
    tools, err := ReadTools(dataDir, vers)
    logger.Infof("-->reading tools %q --> %q", tools, err)
    if err != nil {
        return nil, err
    }
    tmpName := ToolsDir(dataDir, "tmplink-"+agentName)
    toolPath := ToolsDir(dataDir, tools.Version.String())
    logger.Infof("Create symlink %q --> %q", tmpName, tools.Version.String())
    err = utils.Symlink(toolPath, tmpName)
    logger.Infof("-->Create symlink %q", err)
    if err != nil {
        return nil, fmt.Errorf("cannot create tools symlink: %v", err)
    }

    toolsDir := ToolsDir(dataDir, agentName)
    if _, err := os.Stat(toolsDir); err == nil {
        _ = os.RemoveAll(toolsDir)
    }

    err = os.Rename(tmpName, toolsDir)
    logger.Infof("-->Rename %q", err)
    if err != nil {
        return nil, fmt.Errorf("cannot update tools symlink: %v", err)
    }
    logger.Infof("-->Tools %q", tools)
    return tools, nil
}
