package utils_test

import (
	// "path/filepath"

	// jc "github.com/juju/testing/checkers"
	gc "launchpad.net/gocheck"

	"launchpad.net/juju-core/utils"
)

type PathSuite struct {
	Path string
}

var _ = gc.Suite(&PathSuite{})

func (s *PathSuite) SetUpTest(c *gc.C) {
	s.Path = c.MkDir()
}

func (s *PathSuite) TestCreateSymLink(c *gc.C) {
	err := utils.CreateSymLink("symlink", s.Path)
	c.Assert(err, gc.IsNil)
	target, err := utils.Readlink("symlink")
	c.Assert(err, gc.IsNil)
	c.Assert(target, gc.Equals, s.Path)
}
