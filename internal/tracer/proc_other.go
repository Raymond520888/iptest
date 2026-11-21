//go:build !windows

package tracer

import "os/exec"

func hideConsoleWindow(cmd *exec.Cmd) {}
