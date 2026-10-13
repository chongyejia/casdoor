//go:build unix

// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestControlledStartupNonregularFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, dir, "/dev/null"} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			done := make(chan error, 1)
			go func() { _, err := readStartupFile(path); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("nonregular file accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("nonregular input blocked startup preflight")
			}
		})
	}
	regular := filepath.Join(dir, "projected-config")
	if err := os.WriteFile(regular, []byte("bounded"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config-link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	data, err := readStartupFile(link)
	if err != nil || string(data) != "bounded" {
		t.Fatal("regular projected config symlink rejected")
	}
}
