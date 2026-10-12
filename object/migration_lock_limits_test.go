// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func setMigrationTestOptions(t *testing.T, enabled, mdl, row string) {
	t.Helper()
	t.Setenv("CASDOOR_MIGRATION_LOCK_LIMITS_ENABLED", enabled)
	t.Setenv("CASDOOR_MIGRATION_LOCK_WAIT_SECONDS", mdl)
	t.Setenv("CASDOOR_MIGRATION_INNODB_LOCK_WAIT_SECONDS", row)
}

func TestMigrationDSNOffAndOtherDriversPreserveBytes(t *testing.T) {
	for _, enabled := range []string{"", "false"} {
		setMigrationTestOptions(t, enabled, "invalid", "invalid")
		for _, tc := range []struct {
			driver, raw, database, want string
			prefix                      bool
		}{
			{"mysql", "synthetic:@tcp(localhost)/", "casdoor", "synthetic:@tcp(localhost)/casdoor", true},
			{"mysql", "legacy-unparsed-prefix?x=1", "db", "legacy-unparsed-prefix?x=1db", true},
			{"mysql", "synthetic:@tcp(localhost)/adapter", "ignored", "synthetic:@tcp(localhost)/adapter", false},
			{"postgres", "postgres-original", "ignored", "postgres-original", true},
			{"sqlite3", "file:synthetic", "ignored", "file:synthetic", false},
		} {
			got, err := migrationDataSourceName(tc.driver, tc.raw, tc.database, tc.prefix)
			if err != nil || got != tc.want {
				t.Fatal("off-mode DSN changed")
			}
		}
	}
	setMigrationTestOptions(t, "invalid", "invalid", "invalid")
	got, err := migrationDataSourceName("postgres", "exact non-MySQL input", "ignored", true)
	if err != nil || got != "exact non-MySQL input" {
		t.Fatal("MySQL-only feature affected other driver")
	}
}

func TestMigrationDSNPreservesConnectionOptions(t *testing.T) {
	setMigrationTestOptions(t, "true", "7", "11")
	raw := "synthetic:invented:p@ss@tcp(127.0.0.1:3306)/?charset=utf8mb4&parseTime=true&timeout=3s&sql_mode=%27STRICT_TRANS_TABLES%27&lock_wait_timeout=31536000"
	got, err := migrationDataSourceName("mysql", raw, "casdoor", true)
	if err != nil {
		t.Fatal("valid prefix rejected")
	}
	cfg, err := mysql.ParseDSN(got)
	if err != nil {
		t.Fatal("resolved DSN does not parse")
	}
	if cfg.User != "synthetic" || cfg.Passwd != "invented:p@ss" || cfg.Net != "tcp" || cfg.Addr != "127.0.0.1:3306" || cfg.DBName != "casdoor" || !cfg.ParseTime || cfg.Timeout != 3*time.Second || cfg.Params["charset"] != "utf8mb4" || cfg.Params["sql_mode"] != "'STRICT_TRANS_TABLES'" {
		t.Fatal("original connection options changed")
	}
	if cfg.Params["lock_wait_timeout"] != "7" || cfg.Params["innodb_lock_wait_timeout"] != "11" {
		t.Fatal("session bounds missing")
	}
	second, err := migrationDataSourceName("mysql", got, "", false)
	if err != nil || second != got {
		t.Fatal("complete adapter DSN transformation is not idempotent")
	}
	unix, err := migrationDataSourceName("mysql", "synthetic:@unix(/tmp/owned-synthetic.sock)/adapter?parseTime=true", "", false)
	if err != nil {
		t.Fatal("standalone adapter DSN rejected")
	}
	uc, err := mysql.ParseDSN(unix)
	if err != nil || uc.DBName != "adapter" || uc.Net != "unix" || uc.Params["lock_wait_timeout"] != "7" {
		t.Fatal("standalone adapter options lost")
	}
}

func TestMigrationLockOptionBounds(t *testing.T) {
	for _, tc := range []struct {
		mdl, row         string
		wantMDL, wantRow int
	}{{"", "", 5, 5}, {"1", "30", 1, 30}, {"30", "1", 30, 1}} {
		setMigrationTestOptions(t, "true", tc.mdl, tc.row)
		on, mdl, row, err := migrationLockOptions("mysql")
		if err != nil || !on || mdl != tc.wantMDL || row != tc.wantRow {
			t.Fatal("valid bound rejected")
		}
	}
	for _, bad := range []string{"0", "31", "-1", "+5", " 5", "5 ", "5.0", "abc", "999999999999999999999999999999999999"} {
		for _, key := range []string{"mdl", "row"} {
			mdl, row := "5", "5"
			if key == "mdl" {
				mdl = bad
			} else {
				row = bad
			}
			setMigrationTestOptions(t, "true", mdl, row)
			if _, _, _, err := migrationLockOptions("mysql"); err == nil {
				t.Fatal("invalid bound accepted")
			}
		}
	}
	for _, bad := range []string{"TRUE", "1", "yes", " true", "false "} {
		setMigrationTestOptions(t, bad, "5", "5")
		if _, err := migrationDataSourceName("mysql", "synthetic:@tcp(localhost)/", "casdoor", true); err == nil {
			t.Fatal("invalid enable flag accepted")
		}
	}
}

func TestMigrationDSNRejectsInvalidPrefixWithoutCredentialDisclosure(t *testing.T) {
	setMigrationTestOptions(t, "true", "5", "5")
	for _, tc := range []struct{ raw, db string }{
		{"synthetic:PRIVATE_TEST_MARKER@tcp(127.0.0.1:3306)/existing", "casdoor"},
		{"synthetic:PRIVATE_TEST_MARKER@tcp(127.0.0.1:3306)/", ""},
		{"synthetic:PRIVATE_TEST_MARKER@tcp(127.0.0.1:3306)/", "bad?name"},
		{"synthetic:PRIVATE_TEST_MARKER@tcp(127.0.0.1:3306)/", "bad/name"},
		{"synthetic:PRIVATE_TEST_MARKER@tcp(127.0.0.1:3306)/", "bad\\name"},
		{"synthetic:PRIVATE_TEST_MARKER@tcp(broken", "casdoor"},
	} {
		got, err := migrationDataSourceName("mysql", tc.raw, tc.db, true)
		if err == nil || got != "" {
			t.Fatal("invalid DSN prefix accepted")
		}
		if strings.Contains(err.Error(), "PRIVATE_TEST_MARKER") || strings.Contains(err.Error(), tc.raw) {
			t.Fatal("credential leaked in error")
		}
	}
}
