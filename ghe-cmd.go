package main

import (
	"strings"
)

// GheCmd build GHE Command struct to execute the named command with
// the given arguments.
type GheCmd struct {
	Cmd  string
	Args []string
	// Accept to apply changes directly without requiring user approval
	// the equivalent of adding a `-y` option
	Yes bool
}

func newCmd(name string) *GheCmd {
	ghecmd := &GheCmd{
		Cmd:  name,
		Args: []string{name},
		Yes:  false,
	}
	return ghecmd
}

func newCmdArgs(name string, arg ...string) *GheCmd {
	cmd := newCmd(name)
	cmd.addArgs(arg...)
	return cmd
}
func (c *GheCmd) addArg(arg string) {
	c.Args = append(c.Args, arg)
}

func (c *GheCmd) addArgs(arg ...string) {
	c.Args = append(c.Args, arg...)
}

func (c *GheCmd) String() string {

	cmd := strings.Join(c.Args, " ")
	if c.Yes {
		cmd = "echo y | " + cmd
	}

	return cmd
}

func (c *GheCmd) assumeYes() {
	c.Yes = true
}
