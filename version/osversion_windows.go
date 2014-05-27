package version

import (
	// "runtime"
	"fmt"
	"launchpad.net/juju-core/utils/exec"
	"regexp"
	"strings"
)

func getWinVersion() string {
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
	if val, ok := WindowsVersions[serie]; ok {
		return val
	}
	for key, value := range WindowsVersions {
		reg := regexp.MustCompile(fmt.Sprintf("^%s", key))
		match := reg.MatchString(serie)
		if match {
			return value
		}
	}
	return "unknown"
}

func osVersion() string {
	return getWinVersion()
}
