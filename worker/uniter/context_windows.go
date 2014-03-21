package uniter

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    unitdebug "launchpad.net/juju-core/worker/uniter/debug"
)

// RunHook executes a hook in an environment which allows it to to call back
// into the hook context to execute jujuc tools.
func (ctx *HookContext) RunHook(hookName, charmDir, toolsDir, socketPath string) error {
    var err error
    winhookName := hookName + ".cmd"
    env := ctx.hookVars(charmDir, toolsDir, socketPath)
    debugctx := unitdebug.NewHooksContext(ctx.unit.Name())
    if session, _ := debugctx.FindSession(); session != nil && session.MatchHook(winhookName) {
        logger.Infof("executing %s via debug-hooks", winhookName)
        err = session.RunHook(winhookName, charmDir, env)
    } else {
        err = ctx.runCharmHook(winhookName, charmDir, env)
    }
    return ctx.finalizeContext(winhookName, err)
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