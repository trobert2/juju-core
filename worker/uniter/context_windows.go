package uniter

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

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
        environ = append(vars, "JUJU_RELATION="+r.Name())
        environ = append(vars, "JUJU_RELATION_ID="+r.FakeId())
        environ, _ := ctx.RemoteUnitName()
        environ = append(vars, "JUJU_REMOTE_UNIT="+name)
    }
    return vars
}