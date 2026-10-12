//go:build casdoor_synthetic

package object

import (
	"context"
	"os"
	"testing"

	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

// Only the coordinator's network-isolated synthetic MySQL fixture may run this
// test. Every write targets a connection-local temporary MEMORY table. The
// prefix prevents a lost connection from ever falling through to a real table.
func TestTokenCleanupMySQLSnapshotCompare(t *testing.T) {
	if os.Getenv("CASDOOR_APPROVED_SYNTHETIC_CLEANUP") != "temporary-table-only" {
		t.Skip("isolated synthetic MySQL required")
	}
	engine, err := xorm.NewEngine("mysql", "root:@tcp(127.0.0.1:3306)/casdoor?charset=utf8mb4&timeout=3s&readTimeout=5s&writeTimeout=5s&lock_wait_timeout=5&innodb_lock_wait_timeout=5")
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMaxOpenConns(1)
	engine.SetMaxIdleConns(1)
	engine.SetConnMaxLifetime(0)
	const table = "casdoor_cleanup_validation_20261012_token"
	engine.SetTableMapper(core.NewPrefixMapper(core.SnakeMapper{}, "casdoor_cleanup_validation_20261012_"))
	old := ormer
	ormer = &Ormer{driverName: "mysql", Engine: engine}
	t.Cleanup(func() { ormer = old; engine.Close() })
	if _, err = engine.Exec("CREATE TEMPORARY TABLE " + table + " (owner VARCHAR(100) NOT NULL,name VARCHAR(100) NOT NULL,organization VARCHAR(100),created_time VARCHAR(100),expires_in BIGINT,refresh_token VARCHAR(500),refresh_token_hash VARCHAR(100),application VARCHAR(100),access_token VARCHAR(500),access_token_hash VARCHAR(100),PRIMARY KEY(owner,name)) ENGINE=MEMORY DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci"); err != nil {
		t.Fatal(err)
	}
	base := Token{Owner: "Owner", Name: "same-key", Organization: "synthetic", CreatedTime: "2026-01-01T00:00:00Z", ExpiresIn: 3600, RefreshToken: "opaque-old", RefreshTokenHash: "hash-old", AccessToken: "access-old", AccessTokenHash: "ahash-old", Application: "app-old"}
	reset := func() {
		t.Helper()
		if _, err := engine.Exec("DELETE FROM " + table); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.Exec("INSERT INTO "+table+" (owner,name,organization,created_time,expires_in,refresh_token,refresh_token_hash,application,access_token,access_token_hash) VALUES (?,?,?,?,?,?,?,?,?,?)", base.Owner, base.Name, base.Organization, base.CreatedTime, base.ExpiresIn, base.RefreshToken, base.RefreshTokenHash, base.Application, base.AccessToken, base.AccessTokenHash); err != nil {
			t.Fatal(err)
		}
	}
	changes := []struct {
		column string
		value  interface{}
	}{
		{"owner", "owner"}, {"name", "SAME-key"}, {"organization", "SYNTHETIC"}, {"created_time", "2026-01-02T00:00:00Z"}, {"expires_in", 7200},
		{"refresh_token", "opaque-OLD"}, {"refresh_token_hash", "hash-OLD"}, {"application", "APP-old"}, {"access_token", "access-OLD"}, {"access_token_hash", "ahash-OLD"},
		{"refresh_token", "opaque-old "},
	}
	for _, c := range changes {
		t.Run(c.column, func(t *testing.T) {
			reset()
			if _, err := engine.Exec("UPDATE "+table+" SET "+c.column+" = ?", c.value); err != nil {
				t.Fatal(err)
			}
			affected, err := deleteTokenCleanupSnapshot(&base)
			if err != nil || affected != 0 {
				t.Fatalf("changed row deleted: affected=%d err=%v", affected, err)
			}
			rows, err := engine.QueryString("SELECT COUNT(*) AS n FROM " + table)
			if err != nil || len(rows) != 1 || rows[0]["n"] != "1" {
				t.Fatal("changed row missing")
			}
		})
	}
	reset()
	affected, err := deleteTokenCleanupSnapshot(&base)
	if err != nil || affected != 1 {
		t.Fatalf("unchanged row: affected=%d err=%v", affected, err)
	}
	affected, err = deleteTokenCleanupSnapshot(&base)
	if err != nil || affected != 0 {
		t.Fatal("already deleted not idempotent")
	}
	reset()
	if _, err := engine.Exec("UPDATE " + table + " SET organization=NULL,created_time=NULL,expires_in=NULL,refresh_token=NULL,refresh_token_hash=NULL,application=NULL,access_token=NULL,access_token_hash=NULL"); err != nil {
		t.Fatal(err)
	}
	nullRow := Token{Owner: base.Owner, Name: base.Name}
	affected, err = deleteTokenCleanupSnapshot(&nullRow)
	if err != nil || affected != 1 {
		t.Fatalf("NULL empty handling: %d %v", affected, err)
	}
	reset()
	newRow := base
	newRow.Name = "new-refresh-key"
	if _, err = engine.Exec("INSERT INTO "+table+" (owner,name,organization,created_time,expires_in,refresh_token,refresh_token_hash,application,access_token,access_token_hash) VALUES (?,?,?,?,?,?,?,?,?,?)", newRow.Owner, newRow.Name, newRow.Organization, newRow.CreatedTime, newRow.ExpiresIn, newRow.RefreshToken, newRow.RefreshTokenHash, newRow.Application, newRow.AccessToken, newRow.AccessTokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err = deleteTokenCleanupSnapshot(&base); err != nil {
		t.Fatal(err)
	}
	rows, err := engine.QueryString("SELECT name FROM " + table)
	if err != nil || len(rows) != 1 || rows[0]["name"] != newRow.Name {
		t.Fatal("new refresh key changed")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = deleteTokenCleanupSnapshotContext(cancelled, &newRow); err == nil {
		t.Fatal("cancelled SQL was accepted")
	}
	// Only TEMPORARY is allowed; a reconnect can only fail, not remove a base table.
	if _, err = engine.Exec("DROP TEMPORARY TABLE " + table); err != nil {
		t.Fatal(err)
	}
	if _, err = deleteTokenCleanupSnapshot(&base); err == nil {
		t.Fatal("missing temporary table not reported")
	}
}
