// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func controlledFixture(t *testing.T) StartupManifest {
	t.Helper()
	mode, manifest, checksum, attempt, directory, gate := startupMode, startupManifestPath, startupManifestSHA256, startupAttemptID, startupAttemptDirectory, controlledStartup
	create, export := createDatabase, exportData
	t.Cleanup(func() {
		startupMode, startupManifestPath, startupManifestSHA256, startupAttemptID, startupAttemptDirectory, controlledStartup = mode, manifest, checksum, attempt, directory, gate
		createDatabase, exportData = create, export
	})
	for k, v := range map[string]string{
		"driverName": "mysql", "tableNamePrefix": "", "initDataFile": "",
		"dataSourceName": "synthetic:synthetic@tcp(127.0.0.1:3306)/", "dbName": "synthetic",
		"CASDOOR_BUILTIN_ISOLATION_ENABLED": "true", "CASDOOR_BUILTIN_ADMIN_IDS": `["synthetic-admin"]`,
		"CASDOOR_BUILTIN_PROVISIONER_APPLICATION":        "admin/app-built-in",
		"CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION":  "admin/app-built-in",
		"CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION": "built-in",
		"CASDOOR_MIGRATION_LOCK_LIMITS_ENABLED":          "true", "CASDOOR_MIGRATION_LOCK_WAIT_SECONDS": "5", "CASDOOR_MIGRATION_INNODB_LOCK_WAIT_SECONDS": "5",
	} {
		t.Setenv(k, v)
	}
	createDatabase, exportData, controlledStartup = false, false, nil
	startupMode, startupAttemptID = "migration-only", "synthetic-attempt"
	var err error
	startupAttemptDirectory, err = filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(startupAttemptDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	startupManifestPath = filepath.Join(startupAttemptDirectory, "manifest.json")
	binary, err := startupExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := startupConfigurationDigest()
	if err != nil {
		t.Fatal(err)
	}
	database, err := startupDatabaseDigest("mysql", "synthetic:synthetic@tcp(127.0.0.1:3306)/synthetic")
	if err != nil {
		t.Fatal(err)
	}
	m := StartupManifest{
		Version: "synthetic-v1", BinarySHA256: binary, ConfigurationSHA256: configuration,
		DatabaseSHA256: database, SchemaBefore: startupDigest("schema-before"), SchemaAfter: startupDigest("schema-after"),
		APIBefore: startupDigest("api-before"), APIAfter: startupDigest("api-after"), BootstrapSHA256: startupDigest("bootstrap"),
		AdapterSHA256: map[string]string{"built-in/api-adapter-built-in": startupDigest("api-adapter"), "built-in/user-adapter-built-in": startupDigest("user-adapter")},
	}
	writeControlledManifest(t, m)
	return m
}

func writeControlledManifest(t *testing.T, m StartupManifest) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(startupManifestPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	startupManifestSHA256 = hex.EncodeToString(h[:])
}

func completedControlledRecord(m StartupManifest) startupRecord {
	u := startupDigest("unchanged-user-policy")
	return startupRecord{Attempt: startupAttemptID, Manifest: startupManifestSHA256, State: "COMPLETED",
		Before: &startupSnapshot{Database: m.DatabaseSHA256, Schema: m.SchemaBefore, API: m.APIBefore, UserPolicy: u, Bootstrap: m.BootstrapSHA256},
		After:  &startupSnapshot{Database: m.DatabaseSHA256, Schema: m.SchemaAfter, API: m.APIAfter, UserPolicy: u, Bootstrap: m.BootstrapSHA256}}
}

func writeControlledRecord(t *testing.T, r startupRecord) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(startupAttemptDirectory, "casdoor-startup-attempt.json")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestControlledStartupLegacyUnchanged(t *testing.T) {
	controlledFixture(t)
	startupMode, startupManifestPath = "", "nonexistent"
	createDatabase, exportData = true, true
	g, err := BeginControlledStartup()
	if g != nil || err != nil {
		t.Fatal("legacy startup unexpectedly gated")
	}
}

func TestControlledStartupRejectsUnsafeInputs(t *testing.T) {
	for _, tc := range []string{"mode", "create", "export", "seed", "driver", "prefix", "directory", "symlink", "lock-off"} {
		t.Run(tc, func(t *testing.T) {
			controlledFixture(t)
			original := startupAttemptDirectory
			switch tc {
			case "mode":
				startupMode = "unknown"
			case "create":
				createDatabase = true
			case "export":
				exportData = true
			case "seed":
				t.Setenv("initDataFile", "synthetic.json")
			case "driver":
				t.Setenv("driverName", "sqlite")
			case "prefix":
				t.Setenv("tableNamePrefix", "other_")
			case "directory":
				if err := os.Chmod(original, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(original, link); err != nil {
					t.Fatal(err)
				}
				startupAttemptDirectory = link
			case "lock-off":
				t.Setenv("CASDOOR_MIGRATION_LOCK_LIMITS_ENABLED", "false")
			}
			if _, err := BeginControlledStartup(); err == nil {
				t.Fatal("unsafe input accepted")
			}
			if _, err := os.Stat(filepath.Join(original, "casdoor-startup-attempt.json")); !os.IsNotExist(err) {
				t.Fatal("unsafe input created migration fence")
			}
		})
	}
}

func TestControlledStartupManifestBinding(t *testing.T) {
	for _, tc := range []string{"checksum", "binary", "authority", "passwordless", "adapter", "version"} {
		t.Run(tc, func(t *testing.T) {
			m := controlledFixture(t)
			switch tc {
			case "checksum":
				startupManifestSHA256 = strings.Repeat("0", 64)
			case "binary":
				m.BinarySHA256 = startupDigest("wrong-binary")
				writeControlledManifest(t, m)
			case "authority":
				t.Setenv("CASDOOR_BUILTIN_ADMIN_IDS", `["other-admin"]`)
			case "passwordless":
				t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", "other")
			case "adapter":
				delete(m.AdapterSHA256, "built-in/user-adapter-built-in")
				writeControlledManifest(t, m)
			case "version":
				m.Version = ""
				writeControlledManifest(t, m)
			}
			if _, err := BeginControlledStartup(); err == nil {
				t.Fatal("unbound manifest accepted")
			}
			if _, err := os.Stat(filepath.Join(startupAttemptDirectory, "casdoor-startup-attempt.json")); !os.IsNotExist(err) {
				t.Fatal("failed binding created migration fence")
			}
		})
	}
}

func TestControlledStartupExclusiveFence(t *testing.T) {
	controlledFixture(t)
	g, err := BeginControlledStartup()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(g.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unprotected migration fence")
	}
	before, err := os.ReadFile(g.path)
	if err != nil {
		t.Fatal(err)
	}
	var r startupRecord
	if json.Unmarshal(before, &r) != nil || r.State != "STARTED" || r.After != nil {
		t.Fatal("unexpected pre-DB fence state")
	}
	startupAttemptID = "another-attempt"
	if _, err := BeginControlledStartup(); err == nil {
		t.Fatal("existing attempt overwritten")
	}
	after, err := os.ReadFile(g.path)
	if err != nil || string(after) != string(before) {
		t.Fatal("failure changed original fence")
	}
}

func TestControlledStartupCompletedReceiptBinding(t *testing.T) {
	for _, tc := range []string{"valid", "missing", "state", "attempt", "manifest", "before", "after", "user-policy", "permissions", "symlink"} {
		t.Run(tc, func(t *testing.T) {
			m := controlledFixture(t)
			startupMode = "serve-without-ddl"
			r := completedControlledRecord(m)
			switch tc {
			case "state":
				r.State = "STARTED"
			case "attempt":
				r.Attempt = "other-attempt"
			case "manifest":
				r.Manifest = startupDigest("other-manifest")
			case "before":
				r.Before.Schema = startupDigest("wrong-schema")
			case "after":
				r.After.API = startupDigest("wrong-api")
			case "user-policy":
				r.After.UserPolicy = startupDigest("changed-policy")
			}
			if tc != "missing" {
				p := writeControlledRecord(t, r)
				if tc == "permissions" {
					if err := os.Chmod(p, 0644); err != nil {
						t.Fatal(err)
					}
				}
				if tc == "symlink" {
					if err := os.Rename(p, p+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(p+".original", p); err != nil {
						t.Fatal(err)
					}
				}
			}
			g, err := BeginControlledStartup()
			if tc == "valid" {
				if err != nil || g == nil {
					t.Fatal("valid completed receipt rejected")
				}
			} else if err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
}

func TestControlledStartupEffectiveConfiguration(t *testing.T) {
	controlledFixture(t)
	base, err := startupConfigurationDigest()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CASDOOR_MIGRATION_LOCK_WAIT_SECONDS", "")
	t.Setenv("CASDOOR_MIGRATION_INNODB_LOCK_WAIT_SECONDS", "")
	got, err := startupConfigurationDigest()
	if err != nil || got != base {
		t.Fatal("effective default5 differs from explicit5")
	}
	for _, key := range []string{"CASDOOR_BUILTIN_ISOLATION_ENABLED", "CASDOOR_BUILTIN_ADMIN_IDS", "CASDOOR_BUILTIN_PROVISIONER_APPLICATION", "CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", "CASDOOR_MIGRATION_LOCK_LIMITS_ENABLED", "CASDOOR_MIGRATION_LOCK_WAIT_SECONDS", "CASDOOR_MIGRATION_INNODB_LOCK_WAIT_SECONDS"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "different")
			h, err := startupConfigurationDigest()
			if err == nil && h == base {
				t.Fatal("effective field omitted")
			}
		})
	}
}

func TestControlledStartupFileBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 65537)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStartupFile(p); err == nil {
		t.Fatal("oversized file accepted")
	}
	if _, err := readStartupFile(p + "-missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(p, []byte("bounded"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readStartupFile(p)
	if err != nil || string(got) != "bounded" {
		t.Fatal("bounded file rejected")
	}
}

func TestControlledStartupServeGuardsDDL(t *testing.T) {
	controlledFixture(t)
	startupMode = "serve-without-ddl"
	for name, fn := range map[string]func(){"tables": CreateTables, "ormer": func() { (&Ormer{}).createTable() }, "seed": InitDb} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil || !strings.Contains(r.(string), "forbidden") {
					t.Fatal("expected explicit guard before database access")
				}
			}()
			fn()
		})
	}
	if err := (&Ormer{}).CreateDatabase(); err == nil {
		t.Fatal("runtime database creation allowed")
	}
}

func TestControlledStartupAdapterScope(t *testing.T) {
	controlledFixture(t)
	a := &Adapter{Owner: "built-in", Name: "api-adapter-built-in", Table: "casbin_api_rule", UseSameDb: true}
	controlledStartup = &ControlledStartup{manifest: StartupManifest{AdapterSHA256: map[string]string{a.GetId(): startupAdapterDigest(a)}}}
	if err := ValidateStartupAdapterBinding(a); err != nil {
		t.Fatal(err)
	}
	a.Password = "synthetic-rotated-secret"
	if err := ValidateStartupAdapterBinding(a); err != nil {
		t.Fatal("credential rotation changed target binding")
	}
	a.Table = "different_table"
	if err := ValidateStartupAdapterBinding(a); err == nil {
		t.Fatal("changed table accepted")
	}
}

func TestControlledStartupDatabaseTargets(t *testing.T) {
	for _, tc := range []string{"database", "host", "user", "adapter-host-rewrite", "malformed"} {
		t.Run(tc, func(t *testing.T) {
			m := controlledFixture(t)
			switch tc {
			case "database":
				t.Setenv("dbName", "different")
			case "host":
				t.Setenv("dataSourceName", "synthetic:synthetic@tcp(192.0.2.1:3306)/")
			case "user":
				t.Setenv("dataSourceName", "different:synthetic@tcp(127.0.0.1:3306)/")
			case "adapter-host-rewrite":
				previous := isCloudIntranet
				isCloudIntranet = false
				t.Cleanup(func() { isCloudIntranet = previous })
				t.Setenv("dataSourceName", "synthetic:synthetic@tcp(dbi.synthetic.invalid:3306)/")
				var err error
				m.DatabaseSHA256, err = startupDatabaseDigest("mysql", "synthetic:synthetic@tcp(dbi.synthetic.invalid:3306)/synthetic")
				if err != nil {
					t.Fatal(err)
				}
				writeControlledManifest(t, m)
			case "malformed":
				t.Setenv("dataSourceName", "invalid")
			}
			if _, err := BeginControlledStartup(); err == nil {
				t.Fatal("unbound database accepted before connection")
			}
			if _, err := os.Stat(filepath.Join(startupAttemptDirectory, "casdoor-startup-attempt.json")); !os.IsNotExist(err) {
				t.Fatal("database binding failure created fence")
			}
		})
	}
	t.Run("credential-rotation", func(t *testing.T) {
		m := controlledFixture(t)
		t.Setenv("dataSourceName", "synthetic:rotated@tcp(127.0.0.1:3306)/")
		if err := verifyStartupDatabaseTargets(m.DatabaseSHA256); err != nil {
			t.Fatal("password-only rotation changed non-secret target")
		}
	})
	t.Run("engine-boundary", func(t *testing.T) {
		m := controlledFixture(t)
		controlledStartup = &ControlledStartup{manifest: m}
		if _, err := NewAdapter("mysql", "synthetic:synthetic@tcp(192.0.2.1:3306)/", "synthetic"); err == nil || !strings.Contains(err.Error(), "before connection") {
			t.Fatal("main engine did not refuse target before opening")
		}
		a := &Adapter{Owner: "built-in", Name: "api-adapter-built-in", Table: "casbin_api_rule", UseSameDb: true}
		controlledStartup.manifest.AdapterSHA256[a.GetId()] = startupAdapterDigest(a)
		t.Setenv("dataSourceName", "synthetic:synthetic@tcp(192.0.2.1:3306)/")
		if err := a.InitAdapter(); err == nil || !strings.Contains(err.Error(), "before connection") || a.engine != nil {
			t.Fatal("policy engine did not refuse target before opening")
		}
	})
}
