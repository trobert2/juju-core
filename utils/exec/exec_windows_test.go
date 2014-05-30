// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package exec_test

import (
	"strings"

	jc "github.com/juju/testing/checkers"
	gc "launchpad.net/gocheck"

	"launchpad.net/juju-core/testing"
	"launchpad.net/juju-core/utils/exec"
)

type execSuite struct {
	testing.BaseSuite
}

var _ = gc.Suite(&execSuite{})

func (*execSuite) TestRunCommands(c *gc.C) {
	newDir := c.MkDir()
	// newDir =

	for i, test := range []struct {
		message     string
		commands    string
		workingDir  string
		environment []string
		stdout      string
		stderr      string
		code        int
	}{
		{
			message:  "test stdout capture",
			commands: "echo testing_stdout",
			stdout:   "testing_stdout\r\n",
		}, {
			message:  "test return code",
			commands: "exit 42",
			code:     42,
		}, {
			message:    "test working dir",
			commands:   `(Get-Item -Path ".\" -Verbose).FullName`,
			workingDir: newDir,
			stdout:     strings.Replace(newDir, "/", "\\", -1) + "\r\n",
		},
		// }, {
		// 	message:     "test environment",
		// 	commands:    "echo $OMG_IT_WORKS",
		// 	environment: []string{`OMG_IT_WORKS=like magic`},
		// 	stdout:      "like magic\n",
		// },
	} {
		c.Logf("%v: %s", i, test.message)

		result, err := exec.RunCommands(
			exec.RunParams{
				Commands:    test.commands,
				WorkingDir:  test.workingDir,
				Environment: test.environment,
			})
		c.Assert(err, gc.IsNil)
		c.Assert(string(result.Stdout), gc.Equals, test.stdout)
		c.Assert(result.Code, gc.Equals, test.code)
	}
}

func (*execSuite) TestExecUnknownCommand(c *gc.C) {
	result, err := exec.RunCommands(
		exec.RunParams{
			Commands: "unknown-command",
		},
	)
	c.Assert(err, gc.IsNil)
	c.Assert(result.Stdout, gc.HasLen, 0)
	compare := "The term 'unknown-command' is not recognized as the name of a cmdlet, function, "
	compare += "script file, or operable program. Check the spelling of the name, or if a path was "
	compare += "included, verify that the path"
	c.Assert(string(result.Stderr), jc.Contains, compare)
	// 127 is a special bash return code meaning command not found.
	c.Assert(result.Code, gc.Equals, 0)
}
