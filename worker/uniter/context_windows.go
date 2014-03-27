package uniter

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "syscall"

    "launchpad.net/juju-core/windows"
)

var suffixOrder = []string{
    "ps1",
    "cmd",
    "bat",
}

func (ctx *HookContext) getScript (hookFile string) (string, string) {
    for i := range suffixOrder {
        file := hookFile + fmt.Sprintf(".%s", suffixOrder[i])
        if _, err := os.Stat(file); err == nil {
            return file, suffixOrder[i]
        }
    }
    return hookFile, ""
}

func (ctx *HookContext) getCommand (hookFile, suffix string) []string {
    var command []string
    if suffix == "ps1"{
        command = append(command, "powershell")
        command = append(command, "-NonInteractive")
        command = append(command, "-ExecutionPolicy")
        command = append(command, "RemoteSigned")
        command = append(command, "-File")
        command = append(command, hookFile)
        return command
    }
    command = append(command, hookFile)
    return command
}

func RebootRequiredError(err error) bool {
    if err == nil {
        return false
    }
    msg, _ := err.(*exec.ExitError)
    code := msg.Sys().(syscall.WaitStatus).ExitStatus()
    if code == windows.MUST_REBOOT {
        return true
    }
    return false
}

func (ctx *HookContext) finalizeContext(process string, err error) error {
    if err != nil{
        // gsamfira: We need this later to requeue the hook
        if RebootRequiredError(err){
            return err
        }
    }
    writeChanges := err == nil
    for id, rctx := range ctx.relations {
        if writeChanges {
            if e := rctx.WriteSettings(); e != nil {
                e = fmt.Errorf(
                    "could not write settings from %q to relation %d: %v",
                    process, id, e,
                )
                logger.Errorf("%v", e)
                if err == nil {
                    err = e
                }
            }
        }
        rctx.ClearCache()
    }
    return err
}

func (ctx *HookContext) runCharmHook(hookName, charmDir string, env []string) error {
    hookFile := filepath.Join(charmDir, "hooks", hookName)
    hookFileSlash := filepath.ToSlash(hookFile)
    // we get the correct file name and the suffix
    suffixedHook, suffix := ctx.getScript(hookFileSlash)
    com := ctx.getCommand(suffixedHook, suffix)
    logger.Infof("Running hook file: %q", hookFileSlash)

    ps := exec.Command(com[0], com[1:]...)
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

func (ctx *HookContext) hookVars(charmDir, toolsDir, socketPath string) []string {
    environ := os.Environ()
    for i:=0; i<len(environ); i++ {
        if environ[i][:5] == "Path=" {
            environ[i] = fmt.Sprintf("Path=%s", filepath.FromSlash(toolsDir) + ";" + os.Getenv("PATH"))
        }
    }

    environ = append(environ, "CHARM_DIR=" + filepath.FromSlash(charmDir))
    environ = append(environ, "JUJU_CONTEXT_ID=" + ctx.id)
    environ = append(environ, "JUJU_AGENT_SOCKET=" + socketPath)
    environ = append(environ, "JUJU_UNIT_NAME=" + ctx.unit.Name())
    environ = append(environ, "JUJU_ENV_UUID=" + ctx.uuid)
    environ = append(environ, "JUJU_ENV_NAME=" + ctx.envName)
    environ = append(environ, "JUJU_API_ADDRESSES=" + strings.Join(ctx.apiAddrs, " "))

    if r, found := ctx.HookRelation(); found {
        environ = append(environ, "JUJU_RELATION="+r.Name())
        environ = append(environ, "JUJU_RELATION_ID="+r.FakeId())
        name, _ := ctx.RemoteUnitName()
        environ = append(environ, "JUJU_REMOTE_UNIT="+name)
    }
    return environ
}