package uniter

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "strconv"
    // "syscall"

    "launchpad.net/juju-core/juju/osenv"
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
        if strings.ToUpper(environ[i][:5]) == "PATH=" {
            environ[i] = fmt.Sprintf("Path=%s", filepath.FromSlash(toolsDir) + ";" + os.Getenv("PATH"))
        }
        if strings.ToUpper(environ[i][:13]) == "PSMODULEPATH=" {
            charmModules := filepath.Join(charmDir, "Modules")
            hookModules := filepath.Join(charmDir, "hooks", "Modules")
            psModulePath := os.Getenv("PSMODULEPATH") + ";" + charmModules + ";" + hookModules
            environ[i] = fmt.Sprintf("PSModulePath=%s", psModulePath)
        }
    }

    environ = append(environ, "CHARM_DIR=" + filepath.FromSlash(charmDir))
    environ = append(environ, "JUJU_CONTEXT_ID=" + ctx.id)
    environ = append(environ, "JUJU_AGENT_SOCKET=" + socketPath)
    environ = append(environ, "JUJU_UNIT_NAME=" + ctx.unit.Name())
    environ = append(environ, "JUJU_ENV_UUID=" + ctx.uuid)
    environ = append(environ, "JUJU_ENV_NAME=" + ctx.envName)
    environ = append(environ, "JUJU_API_ADDRESSES=" + strings.Join(ctx.apiAddrs, " "))
    environ = append(environ, "JUJU_MUST_REBOOT=" + strconv.Itoa(osenv.MustReboot))

    if r, found := ctx.HookRelation(); found {
        environ = append(environ, "JUJU_RELATION="+r.Name())
        environ = append(environ, "JUJU_RELATION_ID="+r.FakeId())
        name, _ := ctx.RemoteUnitName()
        environ = append(environ, "JUJU_REMOTE_UNIT="+name)
    }
    return environ
}