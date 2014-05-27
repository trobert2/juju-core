package windows

import (
	"strconv"

	"launchpad.net/juju-core/utils/exec"
)

func Reboot(when int) error {
	cmd := []string{
		"shutdown.exe",
		"-r",
		"-t",
		strconv.Itoa(when),
	}
	_, err := exec.RunCommand(cmd)
	if err != nil {
		return err
	}
	return nil
}
