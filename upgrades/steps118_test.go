// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package upgrades_test

import (
	gc "launchpad.net/gocheck"

	"launchpad.net/juju-core/testing/testbase"
	"launchpad.net/juju-core/upgrades"
)

type steps118Suite struct {
	testbase.LoggingSuite
}

var _ = gc.Suite(&steps118Suite{})

var expectedSteps = []string{
	"make $DATADIR/locks owned by ubuntu:ubuntu",
	"generate system ssh key",
	"update rsyslog port",
	"install rsyslog-gnutls",
	"remove deprecated attribute values",
}

func (s *steps118Suite) TestUpgradeOperationsContent(c *gc.C) {
	upgradeSteps := upgrades.StepsFor118()
	c.Assert(upgradeSteps, gc.HasLen, len(expectedSteps))
	assertExpectedSteps(c, upgradeSteps, expectedSteps)
}
