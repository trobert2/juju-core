// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
    "fmt"
    "os"
    "path/filepath"

    "launchpad.net/juju-core/cmd"
)


// Main is not redundant with main(), because it provides an entry point
// for testing with arbitrary command line arguments.
func Main(args []string) {
    var code int = 1
    var err error
    commandName := filepath.Base(args[0])
    if commandName == "jujud" {
        code, err = jujuDMain(args)
    } else if commandName == "jujuc" {
        fmt.Fprint(os.Stderr, jujudDoc)
        code = 2
        err = fmt.Errorf("jujuc should not be called directly")
    } else if commandName == "juju-run" {
        code = cmd.Main(&RunCommand{}, cmd.DefaultContext(), args[1:])
    } else {
        code, err = jujuCMain(commandName, args)
    }
    if err != nil {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
    }
    os.Exit(code)
}