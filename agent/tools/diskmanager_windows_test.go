package tools_test

import (
	"encoding/json"

	gc "launchpad.net/gocheck"

	agenttools "launchpad.net/juju-core/agent/tools"
	coretesting "launchpad.net/juju-core/testing"
	coretools "launchpad.net/juju-core/tools"
)

func (s *DiskManagerSuite) assertToolsContents(c *gc.C, t *coretools.Tools, files []*coretesting.TarFile) {
	var wantNames []string
	for _, f := range files {
		wantNames = append(wantNames, f.Header.Name)
	}
	wantNames = append(wantNames, toolsFile)
	dir := s.manager.(*agenttools.DiskManager).SharedToolsDir(t.Version)
	assertDirNames(c, dir, wantNames)
	expectedFileContents, err := json.Marshal(t)
	c.Assert(err, gc.IsNil)
	assertFileContents(c, dir, toolsFile, string(expectedFileContents), 0200)
	for _, f := range files {
		assertFileContents(c, dir, f.Header.Name, f.Contents, 0400)
	}
	gotTools, err := s.manager.ReadTools(t.Version)
	c.Assert(err, gc.IsNil)
	c.Assert(*gotTools, gc.Equals, *t)
}
