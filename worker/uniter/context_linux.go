package uniter

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "strconv"

    "launchpad.net/juju-core/juju/osenv"
)


func (ctx *HookContext) runCharmHook(hookName, charmDir string, env []string) error {
    hookFile := filepath.Join(charmDir, "hooks", hookName)
    logger.Infof("Running hook file: %q", hookFile)
    ps := exec.Command(hookFile)
    ps.Env = env
    ps.Dir = charmDir
    outReader, outWriter, err := os.Pipe()
    if err != nil {
        return fmt.Errorf("cannot make logging pipe: %v", err)
    }
    ps.Stdout = outWriter
    ps.Stderr = outWriter
    hookLogger := &hookLogger{
        r:      outReader,
        done:   make(chan struct{}),
        logger: ctx.GetLogger(hookName),
    }
    go hookLogger.run()
    err = ps.Start()
    outWriter.Close()
    if err == nil {
        err = ps.Wait()
    }
    hookLogger.stop()
    if ee, ok := err.(*exec.Error); ok && err != nil {
        if os.IsNotExist(ee.Err) {
            // Missing hook is perfectly valid, but worth mentioning.
            logger.Infof("skipped %q hook (not implemented) -->%q ", hookName, ee.Err)
            return &missingHookError{hookName}
        }
    }
    return err
}

// hookVars returns an os.Environ-style list of strings necessary to run a hook
// such that it can know what environment it's operating in, and can call back
// into ctx.
func (ctx *HookContext) hookVars(charmDir, toolsDir, socketPath string) []string {
    vars := []string{
        "APT_LISTCHANGES_FRONTEND=none",
        "DEBIAN_FRONTEND=noninteractive",
        "PATH=" + toolsDir + ":" + os.Getenv("PATH"),
        "CHARM_DIR=" + charmDir,
        "JUJU_CONTEXT_ID=" + ctx.id,
        "JUJU_AGENT_SOCKET=" + socketPath,
        "JUJU_UNIT_NAME=" + ctx.unit.Name(),
        "JUJU_ENV_UUID=" + ctx.uuid,
        "JUJU_ENV_NAME=" + ctx.envName,
        "JUJU_API_ADDRESSES=" + strings.Join(ctx.apiAddrs, " "),
        "JUJU_MUST_REBOOT=" + strconv.Itoa(osenv.MustReboot),
    }
    if r, found := ctx.HookRelation(); found {
        vars = append(vars, "JUJU_RELATION="+r.Name())
        vars = append(vars, "JUJU_RELATION_ID="+r.FakeId())
        name, _ := ctx.RemoteUnitName()
        vars = append(vars, "JUJU_REMOTE_UNIT="+name)
    }
    vars = append(vars, ctx.proxySettings.AsEnvironmentValues()...)
    return vars
}