//go:build !unix

// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"errors"
	"os"
)

func openStartupFile(path string) (*os.File, error) {
	return nil, errors.New("controlled startup file handling unsupported on this platform")
}
