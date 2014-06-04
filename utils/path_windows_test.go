package utils_test

import (
	"log"
	"os"

	gc "launchpad.net/gocheck"
	
	"launchpad.net/juju-core/utils"
)

type PathSuite struct {
	Target string
	Link string
}

var _ = gc.Suite(&PathSuite{})

func (s *PathSuite) SetUpTest(c *gc.C) {
	s.Target = c.MkDir()
	s.Link = "symlink"
}

func (s *PathSuite) TearDownTest(c *gc.C) {
	os.Remove(s.Link)
}

func (s *PathSuite) TestCreateSymLink(c *gc.C) {
	target := utils.PathToWindows(s.Target)
	target, _ = utils.GetLongPath(target)

	err := utils.CreateSymLink(s.Link, target)
	if err != nil {
		log.Print(err)
	}
	compare, err := utils.Readlink(s.Link)
	if err != nil {
		log.Print(err)
	}

	c.Assert(err, gc.IsNil)
	c.Assert(err, gc.IsNil)
	c.Assert(compare, gc.Equals, target)
}
