package uniter

import (
    "math/rand"
    "os"
    "os/exec"
    "path/filepath"
    "time"
    "fmt"

    "launchpad.net/juju-core/agent/tools"
    "launchpad.net/juju-core/utils"
    "launchpad.net/juju-core/state/api/uniter"
    "launchpad.net/juju-core/cmd"
    "launchpad.net/juju-core/worker/uniter/charm"
    "launchpad.net/juju-core/worker/uniter/jujuc"
    "launchpad.net/juju-core/worker/uniter/hook"

    "launchpad.net/juju-core/windows"
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

// runHook executes the supplied hook.Info in an appropriate hook context. If
// the hook itself fails to execute, it returns errHookFailed.
func (u *Uniter) runHook(hi hook.Info) (err error) {
    // Prepare context.
    if err = hi.Validate(); err != nil {
        return err
    }

    hookName := string(hi.Kind)
    relationId := -1
    if hi.Kind.IsRelation() {
        relationId = hi.RelationId
        if hookName, err = u.relationers[relationId].PrepareHook(hi); err != nil {
            return err
        }
    }
    hctxId := fmt.Sprintf("%s:%s:%d", u.unit.Name(), hookName, u.rand.Int63())

    lockMessage := fmt.Sprintf("%s: running hook %q", u.unit.Name(), hookName)
    if err = u.acquireHookLock(lockMessage); err != nil {
        return err
    }
    defer u.hookLock.Unlock()

    hctx, err := u.getHookContext(hctxId, relationId, hi.RemoteUnit)
    if err != nil {
        return err
    }
    srv, socketPath, err := u.startJujucServer(hctx)
    if err != nil {
        return err
    }
    defer srv.Close()

    // Run the hook.
    if err := u.writeState(RunHook, Pending, &hi, nil); err != nil {
        return err
    }
    logger.Infof("running %q hook", hookName)
    ranHook := true
    err = hctx.RunHook(hookName, u.charm.Path(), u.toolsDir, socketPath)
    if RebootRequiredError(err){
        logger.Infof("hook %q requested a reboot", hookName)
        if err := u.writeState(RunHook, Queued, &hi, nil); err != nil {
            return err
        }
        time := 60
        logger.Infof("rebooting system in %q", time)
        errReboot := windows.Reboot(time)
        if eeReboot, ok := errReboot.(*exec.Error); ok && eeReboot != nil {
            logger.Infof("Reboot returned error: %q", eeReboot.Err)
        }
        logger.Infof("Stopping uniter due to reboot")
        u.Stop()
    }
    if IsMissingHookError(err) {
        ranHook = false
    } else if err != nil {
        logger.Errorf("hook failed: %s", err)
        u.notifyHookFailed(hookName, hctx)
        return errHookFailed
    }
    if err := u.writeState(RunHook, Done, &hi, nil); err != nil {
        return err
    }
    if ranHook {
        logger.Infof("ran %q hook", hookName)
        u.notifyHookCompleted(hookName, hctx)
    } else {
        logger.Infof("skipped %q hook (missing)", hookName)
    }
    return u.commitHook(hi)
}