package version

import (
    // "runtime"
    "fmt"
    "strings"
    "regexp"
    "launchpad.net/juju-core/utils/exec"
)

// Windows versions come in various flavors:
// Standard, Datacenter, etc. We use regex to match them to one
// of the following. Specify the longest name in a particular serie first
// For example, if we have "Win 2012" and "Win 2012 R2". we specify "Win 2012 R2" first
var WindowsVersions = map[string]string{
    "Microsoft Hyper-V Server 2012 R2": "win2012hvr2",
    "Microsoft Hyper-V Server 2012": "win2012hv",
    "Microsoft Windows Server 2012 R2": "win2012r2",
    "Microsoft Windows Server 2012": "win2012",
    "Windows Storage Server 2012 R2": "win2012r2",
    "Windows Storage Server 2012": "win2012",
}


func readSeries(releaseFile string) string {
    // We don't really need the releaseFile
    _ = releaseFile
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
    for key, value := range WindowsVersions {
        reg := regexp.MustCompile(fmt.Sprintf("^%s", key))
        match := reg.MatchString(serie)
        if(match){
            return value
        }
    }
    return "unknown"
}

func ReleaseVersion() string {
    return ""
}
