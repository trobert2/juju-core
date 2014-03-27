// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package deployer

import (
    "fmt"
    // "io/ioutil"
    "os"
    "path"
    "regexp"
    "strings"

    "launchpad.net/juju-core/agent"
    "launchpad.net/juju-core/agent/tools"
    // "launchpad.net/juju-core/juju/osenv"
    "launchpad.net/juju-core/names"
    "launchpad.net/juju-core/utils"
    "launchpad.net/juju-core/utils/exec"
    "launchpad.net/juju-core/state/api/params"
    // "launchpad.net/juju-core/upstart"
    "launchpad.net/juju-core/version"
    "launchpad.net/juju-core/windows/service"
)

// APICalls defines the interface to the API that the simple context needs.
type APICalls interface {
    ConnectionInfo() (params.DeployerConnectionValues, error)
}

// SimpleContext is a Context that manages unit deployments via upstart
// jobs on the local system.
type SimpleContext struct {

    // api is used to get the current state server addresses at the time the
    // given unit is deployed.
    api APICalls

    // agentConfig returns the agent config for the machine agent that is
    // running the deployer.
    agentConfig agent.Config
}

var _ Context = (*SimpleContext)(nil)

// NewSimpleContext returns a new SimpleContext, acting on behalf of
// the specified deployer, that deploys unit agents as upstart jobs in
// "/etc/init". Paths to which agents and tools are installed are
// relative to dataDir.
func NewSimpleContext(agentConfig agent.Config, api APICalls) *SimpleContext {
    return &SimpleContext{
        api:         api,
        agentConfig: agentConfig,
    }
}

func (ctx *SimpleContext) AgentConfig() agent.Config {
    return ctx.agentConfig
}


func (ctx *SimpleContext) DeployUnit(unitName, initialPassword string) (err error) {
    // Check sanity.
    svc := ctx.winService(unitName)
    if svc.Installed() {
        return fmt.Errorf("unit %q is already deployed", unitName)
    }

    // Link the current tools for use by the new agent.
    tag := names.UnitTag(unitName)
    dataDir := ctx.agentConfig.DataDir()
    logDir := ctx.agentConfig.LogDir()
    _, err = tools.ChangeAgentTools(dataDir, tag, version.Current)
    toolsDir := tools.ToolsDir(dataDir, tag)
    defer removeOnErr(&err, toolsDir)

    result, err := ctx.api.ConnectionInfo()
    if err != nil {
        return err
    }
    logger.Debugf("state addresses: %q", result.StateAddresses)
    logger.Debugf("API addresses: %q", result.APIAddresses)
    containerType := ctx.agentConfig.Value(agent.ContainerType)
    namespace := ctx.agentConfig.Value(agent.Namespace)
    conf, err := agent.NewAgentConfig(
        agent.AgentConfigParams{
            DataDir:           dataDir,
            LogDir:            logDir,
            UpgradedToVersion: version.Current.Number,
            Tag:               tag,
            Password:          initialPassword,
            Nonce:             "unused",
            // TODO: remove the state addresses here and test when api only.
            StateAddresses: result.StateAddresses,
            APIAddresses:   result.APIAddresses,
            CACert:         ctx.agentConfig.CACert(),
            Values: map[string]string{
                agent.ContainerType: containerType,
                agent.Namespace:     namespace,
            },
        })
    if err != nil {
        return err
    }
    if err := conf.Write(); err != nil {
        return err
    }
    defer removeOnErr(&err, conf.Dir())

    // Install a windows service that runs the unit agent.
    logPath := path.Join(logDir, tag+".log")
    jujuServiceWrapper := path.Join(toolsDir, "JujuService.exe")
    cmd := strings.Join([]string{
        path.Join(toolsDir, "jujud.exe"), "unit",
        "--data-dir", dataDir,
        "--unit-name", unitName,
        "--debug", // TODO: propagate debug state sensibly
        "--log-file", logPath,
    }, " ")

    winCmd := &service.Cmd{
        Service:        *svc,
        Description:    "juju unit agent for " + unitName,
        Cmd:            cmd,
        ServiceBin:     jujuServiceWrapper,
    }
    return winCmd.Install()
}

// findUpstartJob tries to find an upstart job matching the
// given unit name in one of these formats:
//   jujud-<deployer-tag>:<unit-tag>.conf (for compatibility)
//   jujud-<unit-tag>.conf (default)
func (ctx *SimpleContext) findJob(unitName string) *service.Service {
    unitsAndJobs, err := ctx.deployedUnitsJobs()
    if err != nil {
        return nil
    }
    if _, ok := unitsAndJobs[unitName]; ok {
        svc := ctx.winService(unitName)
        return svc
    }
    return nil
}

func (ctx *SimpleContext) RecallUnit(unitName string) error {
    logger.Debugf("recallinf unit: %q", unitName)
    svc := ctx.findJob(unitName)
    if svc == nil || !svc.Installed() {
        return fmt.Errorf("unit %q is not deployed", unitName)
    }
    if err := svc.StopAndRemove(); err != nil {
        return err
    }
    logger.Debugf("getting tag for: %q", unitName)
    tag := names.UnitTag(unitName)
    dataDir := ctx.agentConfig.DataDir()
    agentDir := agent.Dir(dataDir, tag)
    // Recursivley change mode to 777 on windows to avoid
    // Operation not permitted
    err := utils.RChmod(agentDir, os.FileMode(0777))
    if err != nil {
        return err
    }
    if err := os.RemoveAll(agentDir); err != nil {
        return err
    }
    toolsDir := tools.ToolsDir(dataDir, tag)
    return os.Remove(toolsDir)
}

var deployedRe = regexp.MustCompile("^(jujud-.*unit-([a-z0-9-]+)-([0-9]+))$")

func (ctx *SimpleContext) deployedUnitsJobs() (map[string]string, error) {
    cmd := []string{
        "powershell",
        "Invoke-Command {",
        `$x = Get-Service "jujud-*"`,
        exec.CheckError,
        "$x.Name",
        "}",
    }
    services, err := exec.RunCommand(cmd)
    if err != nil {
        return nil, err
    }
    units := strings.Split(services, "\r\n")

    installed := make(map[string]string)
    for i := range units {
        if groups := deployedRe.FindStringSubmatch(units[i]); len(groups) == 4 {
            unitName := groups[2] + "/" + groups[3]
            if !names.IsUnit(unitName) {
                continue
            }
            installed[unitName] = groups[1]
        }
    }
    return installed, nil
}

func (ctx *SimpleContext) DeployedUnits() ([]string, error) {
    unitsAndJobs, err := ctx.deployedUnitsJobs()
    if err != nil {
        return nil, err
    }
    var installed []string
    for unitName := range unitsAndJobs {
        installed = append(installed, unitName)
    }
    return installed, nil
}

func (ctx *SimpleContext) getSvcName(unitName string) string {
    logger.Debugf("get svc name: %q", unitName)
    tag := names.UnitTag(unitName)
    svcName := "jujud-" + tag
    return svcName
}

// upstartService returns an upstart.Service corresponding to the specified
// unit.
func (ctx *SimpleContext) winService(unitName string) *service.Service {
    svcName := ctx.getSvcName(unitName)
    svc := service.NewService(svcName)
    return svc
}

func removeOnErr(err *error, path string) {
    if *err != nil {
        if err := os.Remove(path); err != nil {
            logger.Warningf("installer: cannot remove %q: %v", path, err)
        }
    }
}
