package uniter

import (
    "os"
    "strings"

    unitdebug "launchpad.net/juju-core/worker/uniter/debug"
)


// RunHook executes a hook in an environment which allows it to to call back
// into the hook context to execute jujuc tools.
func (ctx *HookContext) RunHook(hookName, charmDir, toolsDir, socketPath string) error {
    var err error
    env := ctx.hookVars(charmDir, toolsDir, socketPath)
    debugctx := unitdebug.NewHooksContext(ctx.unit.Name())
    if session, _ := debugctx.FindSession(); session != nil && session.MatchHook(hookName) {
        logger.Infof("executing %s via debug-hooks", hookName)
        err = session.RunHook(hookName, charmDir, env)
    } else {
        err = ctx.runCharmHook(hookName, charmDir, env)
    }
    return ctx.finalizeContext(hookName, err)
}


// hookVars returns an os.Environ-style list of strings necessary to run a hook
// such that it can know what environment it's operating in, and can call back
// into ctx.
// TODO: gsamfira: env vars for windows
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