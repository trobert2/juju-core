// Copyright 2014 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package filetesting_test

import (
	"io/ioutil"
	"os"

	gc "launchpad.net/gocheck"

	ft "launchpad.net/juju-core/testing/filetesting"
)

func (s *EntrySuite) TestFileCreate(c *gc.C) {
	ft.File{"foobar", "hello", 0644}.Create(c, s.basePath)
	path := s.join("foobar")
	info, err := os.Lstat(path)
	c.Assert(err, gc.IsNil)
	c.Assert(info.Mode()&os.ModePerm, gc.Equals, os.FileMode(0644))
	c.Assert(info.Mode()&os.ModeType, gc.Equals, os.FileMode(0))
	data, err := ioutil.ReadFile(path)
	c.Assert(err, gc.IsNil)
	c.Assert(string(data), gc.Equals, "hello")
}

func (s *EntrySuite) TestDirCreate(c *gc.C) {
	ft.Dir{"path", 0750}.Create(c, s.basePath)
	info, err := os.Lstat(s.join("path"))
	c.Check(err, gc.IsNil)
	c.Check(info.Mode()&os.ModePerm, gc.Equals, os.FileMode(0750))
	c.Check(info.Mode()&os.ModeType, gc.Equals, os.ModeDir)
}
