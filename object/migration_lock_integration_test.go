//go:build casdoor_synthetic

// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Run only in an owned network-none namespace with a synthetic MySQL fixture.
package object

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestMigrationTwoEnginesPhysicalConnections(t *testing.T) {
	if os.Getenv("CASDOOR_APPROVED_SYNTHETIC_LOCK_TEST") != "true" {
		t.Skip("explicit synthetic guard required")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal("network isolation state unknown")
	}
	for _, iface := range interfaces {
		if iface.Name != "lo" && iface.Flags&net.FlagUp != 0 {
			t.Fatal("active external interface forbidden")
		}
	}

	if testing.Short() {
		t.Skip("synthetic DB integration")
	}
	// This opt-in guard is intentional, independent from the migration feature flag.
	// The enclosing runner must prove container network=none and synthetic DB ownership.
	t.Setenv("CASDOOR_MIGRATION_LOCK_LIMITS_ENABLED", "true")
	t.Setenv("CASDOOR_MIGRATION_LOCK_WAIT_SECONDS", "5")
	t.Setenv("CASDOOR_MIGRATION_INNODB_LOCK_WAIT_SECONDS", "5")
	t.Setenv("driverName", "mysql")
	t.Setenv("dataSourceName", "root:@tcp(127.0.0.1:3306)/")
	t.Setenv("dbName", "casdoor")
	if err := (&Ormer{driverName: "mysql"}).CreateDatabase(); err == nil {
		t.Fatal("migration mode admitted database creation")
	}
	if _, err := NewAdapterFromDb("mysql", "unused", "casdoor", nil); err == nil {
		t.Fatal("migration mode admitted an externally supplied pool")
	}
	a, err := NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/", "casdoor")
	if err != nil {
		t.Fatal("primary engine creation failed; details suppressed")
	}
	defer a.Engine.Close()
	adapter := &Adapter{Owner: "built-in", Name: "api-adapter-built-in", UseSameDb: true, Table: "casbin_api_rule"}
	if err := adapter.InitAdapter(); err != nil {
		t.Fatal("adapter engine creation failed; details suppressed")
	}
	defer adapter.engine.Close()
	pools := []*sql.DB{a.Engine.DB().DB, adapter.engine.DB().DB}
	for idx, db := range pools {
		db.SetMaxOpenConns(4)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		first, e := db.Conn(ctx)
		if e != nil {
			cancel()
			t.Fatal("physical connection1 failed")
		}
		defer first.Close()
		second, e := db.Conn(ctx)
		if e != nil {
			first.Close()
			cancel()
			t.Fatal("physical connection2 failed")
		}
		defer second.Close()
		check := func(c *sql.Conn) int64 {
			var id int64
			var mdl, row int
			if e := c.QueryRowContext(ctx, "SELECT CONNECTION_ID(),@@session.lock_wait_timeout,@@session.innodb_lock_wait_timeout").Scan(&id, &mdl, &row); e != nil {
				t.Fatal("session query failed")
			}
			if mdl != 5 || row != 5 {
				t.Fatalf("engine%d physical connection not limited", idx)
			}
			return id
		}
		id1, id2 := check(first), check(second)
		t.Logf("engine=%d initial_physical_connections=%d,%d lock_wait=5 row_wait=5", idx, id1, id2)
		if id1 == id2 {
			t.Fatal("same physical connection reused")
		}
		first.Close()
		second.Close()
		db.SetConnMaxLifetime(time.Nanosecond)
		time.Sleep(time.Millisecond)
		replacement, e := db.Conn(ctx)
		if e != nil {
			t.Fatal("replacement failed")
		}
		id3 := check(replacement)
		t.Logf("engine=%d replacement_physical_connection=%d", idx, id3)
		replacement.Close()
		if id3 == id1 || id3 == id2 {
			t.Fatal("reconnection not observed")
		}
		db.SetConnMaxLifetime(0)
		blocker, e := db.Conn(ctx)
		if e != nil {
			t.Fatal("blocker reservation failed")
		}
		defer func(c *sql.Conn) {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
			defer cleanupCancel()
			c.ExecContext(cleanupCtx, "ROLLBACK")
			c.Close()
		}(blocker)
		if _, e = blocker.ExecContext(ctx, "START TRANSACTION"); e != nil {
			t.Fatal("blocker begin failed")
		}
		rows, e := blocker.QueryContext(ctx, "SELECT * FROM `user` LIMIT 1")
		if e != nil {
			t.Fatal("blocker query failed")
		}
		rows.Close()
		started := time.Now()
		_, alterErr := db.ExecContext(ctx, "ALTER TABLE `user` ADD COLUMN phase4_mdl_must_not_exist varchar(1)")
		elapsed := time.Since(started)
		var myerr *mysql.MySQLError
		_, releaseErr := blocker.ExecContext(context.Background(), "ROLLBACK")
		blocker.Close()
		cancel()
		if releaseErr != nil {
			t.Fatal("synthetic blocker cleanup unconfirmed")
		}
		if !errors.As(alterErr, &myerr) || myerr.Number != 1205 || elapsed < 4*time.Second || elapsed > 10*time.Second {
			t.Fatal("MDL rejection not verified; details suppressed")
		}
		t.Logf("engine=%d mdl_server_timeout_ms=%d error=1205", idx, elapsed.Milliseconds())
		var n int
		if e := db.QueryRow("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='casdoor' AND table_name='user' AND column_name='phase4_mdl_must_not_exist'").Scan(&n); e != nil || n != 0 {
			t.Fatal("failed DDL changed schema or state unknown")
		}
	}
}
