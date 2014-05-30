// Copyright 2013, 2014 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package filetesting

import (
	"io/ioutil"
	"os"

	gc "launchpad.net/gocheck"
	"launchpad.net/juju-core/utils"
)

func (d Dir) Create(c *gc.C, basePath string) Entry {
	path := join(basePath, d.Path)
	err := os.MkdirAll(path, d.Perm)
	c.Assert(err, gc.IsNil)
	// err = os.Chmod(path, d.Perm)
	// c.Assert(err, gc.IsNil)
	return d
}

func (d Dir) Check(c *gc.C, basePath string) Entry {
	_, err := os.Lstat(join(basePath, d.Path))
	if !c.Check(err, gc.IsNil) {
		return d
	}
	// c.Check(fileInfo.Mode()&os.ModePerm, gc.Equals, d.Perm)
	// c.Check(fileInfo.Mode()&os.ModeType, gc.Equals, os.ModeDir)
	return d
}

func (f File) Check(c *gc.C, basePath string) Entry {
	path := join(basePath, f.Path)
	_, err := os.Lstat(path)
	if !c.Check(err, gc.IsNil) {
		return f
	}
	// mode := fileInfo.Mode()
	// c.Check(mode&os.ModeType, gc.Equals, os.FileMode(0))
	// c.Check(mode&os.ModePerm, gc.Equals, f.Perm)
	data, err := ioutil.ReadFile(path)
	c.Check(err, gc.IsNil)
	c.Check(string(data), gc.Equals, f.Data)
	return f
}

func (s Symlink) Create(c *gc.C, basePath string) Entry {
	err := utils.Symlink(s.Link, join(basePath, s.Path))
	c.Assert(err, gc.IsNil)
	return s
}
