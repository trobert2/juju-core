package tools_test

import (
	gc "launchpad.net/gocheck"

	"launchpad.net/juju-core/testing/testbase"
)

func (t *ToolsSuite) TestPackageDependencies(c *gc.C) {
	// This test is to ensure we don't bring in dependencies on state, environ
	// or any of the other bigger packages that'll drag in yet more dependencies.
	// Only imports that start with "launchpad.net/juju-core" are checked, and the
	// resulting slice has that prefix removed to keep the output short.
	c.Assert(testbase.FindJujuCoreImports(c, "launchpad.net/juju-core/agent/tools"),
		gc.DeepEquals,
		[]string{"juju/arch", "tools", "utils/set", "version"})
}
