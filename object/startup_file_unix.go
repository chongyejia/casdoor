//go:build unix

// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"os"
	"syscall"
)

// O_NONBLOCK prevents a FIFO (including a raced replacement) from hanging the
// preflight before f.Stat can reject it. Symlinks to regular projected config
// files remain supported; receipt paths have a separate no-symlink check.
func openStartupFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
