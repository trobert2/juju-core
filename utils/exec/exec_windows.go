package main

import (
    "fmt"
    "os/exec"
    "bytes"
    "os"
)


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
