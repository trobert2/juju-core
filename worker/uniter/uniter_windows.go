package uniter

import (
    stderrors "errors"
    "fmt"
    "math/rand"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/juju/loggo"
    "launchpad.net/tomb"

    "launchpad.net/juju-core/agent/tools"
    corecharm "launchpad.net/juju-core/charm"
    "launchpad.net/juju-core/charm/hooks"
    "launchpad.net/juju-core/cmd"
    "launchpad.net/juju-core/environs/config"
    "launchpad.net/juju-core/juju/osenv"
    "launchpad.net/juju-core/state/api/params"
    "launchpad.net/juju-core/state/api/uniter"
    apiwatcher "launchpad.net/juju-core/state/api/watcher"
    "launchpad.net/juju-core/state/watcher"
    "launchpad.net/juju-core/utils"
    "launchpad.net/juju-core/utils/exec"
    "launchpad.net/juju-core/utils/fslock"
    "launchpad.net/juju-core/worker/uniter/charm"
    "launchpad.net/juju-core/worker/uniter/hook"
    "launchpad.net/juju-core/worker/uniter/jujuc"
    "launchpad.net/juju-core/worker/uniter/relation"
)


func (u *Uniter) init(unitTag string) (err error) {
    defer utils.ErrorContextf(&err, "failed to initialize uniter for %q", unitTag)
    u.unit, err = u.st.Unit(unitTag)
    if err != nil {
        return err
    }
    if err = u.setupLocks(); err != nil {
        return err
    }
    u.toolsDir = tools.ToolsDir(u.dataDir, unitTag)
    if err := EnsureJujucSymlinks(u.toolsDir); err != nil {
        return err
    }
    u.baseDir = filepath.Join(u.dataDir, "agents", unitTag)
    u.relationsDir = filepath.Join(u.baseDir, "state", "relations")
    if err := os.MkdirAll(u.relationsDir, 0755); err != nil {
        return err
    }
    u.service, err = u.st.Service(u.unit.ServiceTag())
    if err != nil {
        return err
    }
    var env *uniter.Environment
    env, err = u.st.Environment()
    if err != nil {
        return err
    }
    u.uuid = env.UUID()
    u.envName = env.Name()

    runListenerSocketPath := filepath.Join(u.baseDir, RunListenerFile)
    //TODO: gsamfira: This is a bit hacky. Would prefer implementing
    //named pipes on windows
    u.tcpSock, err = utils.WriteSocketFile(runListenerSocketPath)
    if err != nil {
        return err
    }

    logger.Debugf("starting juju-run listener on:%s", u.tcpSock)
    u.runListener, err = NewRunListener(u, u.tcpSock)
    if err != nil {
        return err
    }

    u.relationers = map[int]*Relationer{}
    u.relationHooks = make(chan hook.Info)
    u.charm = charm.NewGitDir(filepath.Join(u.baseDir, "charm"))
    deployerPath := filepath.Join(u.baseDir, "state", "deployer")
    bundles := charm.NewBundlesDir(filepath.Join(u.baseDir, "state", "bundles"))
    u.deployer = charm.NewGitDeployer(u.charm.Path(), deployerPath, bundles)
    u.sf = NewStateFile(filepath.Join(u.baseDir, "state", "uniter"))
    u.rand = rand.New(rand.NewSource(time.Now().Unix()))
    return nil
}