package exec

import (
    "bytes"
    "os/exec"
    "syscall"
)

// RunCommands executes the Commands specified in the RunParams using
// '/bin/bash -s', passing the commands through as stdin, and collecting
// stdout and stderr.  If a non-zero return code is returned, this is
// collected as the code for the response and this does not classify as an
// error.
func RunCommands(run RunParams) (*ExecResponse, error) {
    ps := exec.Command("/bin/bash", "-s")
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