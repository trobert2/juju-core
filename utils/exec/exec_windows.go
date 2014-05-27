package exec

import (
	"bytes"
	"os/exec"
	"syscall"
)

var CheckError = ";if($? -eq $false){ exit 11 };"

func RunPSCommand(script string) (string, error) {
	cmd := []string{
		"powershell",
		"-Command",
		`"`,
		`$ErrorActionPreference = 'Stop';`,
		script,
		`"`,
	}
	return RunCommand(cmd)
}

func RunCommands(run RunParams) (*ExecResponse, error) {
	ps := exec.Command("powershell.exe", "-noprofile", "-noninteractive", "-command", "$input|iex")
	if run.Environment != nil {
		ps.Env = run.Environment
	}
	if run.WorkingDir != "" {
		ps.Dir = run.WorkingDir
	}
	ps.Stdin = bytes.NewBufferString(run.Commands)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	ps.Stdout = stdout
	ps.Stderr = stderr

	err := ps.Start()
	if err == nil {
		err = ps.Wait()
	}
	result := &ExecResponse{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if ee, ok := err.(*exec.ExitError); ok && err != nil {
		status := ee.ProcessState.Sys().(syscall.WaitStatus)
		if status.Exited() {
			// A non-zero return code isn't considered an error here.
			result.Code = status.ExitStatus()
			err = nil
		}
		logger.Infof("run result: %v", ee)
	}
	return result, err
}
