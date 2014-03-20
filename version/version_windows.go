package version

import (
    "runtime"
    "strings"
    "launchpad.net/juju-core/utils/exec"
)


var WindowsVersions = map[string]string{
    "Microsoft Hyper-V Server 2012 R2": "win2012hvr2",
    "Microsoft Hyper-V Server 2012": "win2012hv",
}


// Current gives the current version of the system.  If the file
// "FORCE-VERSION" is present in the same directory as the running
// binary, it will override this.
var Current = Binary{
    Number: MustParse(version),
    Series: readSeries(),
    Arch:   ubuntuArch(runtime.GOARCH),
}

// TODO: gsamfira: see why this fails 
func readSeries() string {
    // return "win2012hvr2"
    cmd := []string{
        "powershell",
        "Invoke-Command {",
        `$x = gwmi Win32_OperatingSystem`,
        exec.CheckError,
        `$x.Name.Split('|')[0]`,
        exec.CheckError,
        "}",
    }
    out, err := exec.RunCommand(cmd)
    if err != nil {
        return "unknown"
    }
    serie := strings.TrimSpace(out)
    if val,ok := WindowsVersions[serie]; ok {
        return val
    }
    return "unknown"
}

func ReleaseVersion() string {
    return ""
}