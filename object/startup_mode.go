// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casdoor/casdoor/conf"
	"github.com/go-sql-driver/mysql"
)

// Controlled startup requires a manifest bound to the reviewed artifact and a
// pre-provisioned persistent directory. The application cannot attest storage
// durability; operators must verify it before migration. No reset is provided.
var (
	startupMode, startupManifestPath, startupManifestSHA256, startupAttemptID, startupAttemptDirectory string
	controlledStartup                                                                                  *ControlledStartup
	startupHex                                                                                         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	startupName                                                                                        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	startupTable                                                                                       = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

type StartupManifest struct {
	ConfigurationSHA256 string            `json:"configurationSha256"`
	Version             string            `json:"version"`
	BinarySHA256        string            `json:"binarySha256"`
	DatabaseSHA256      string            `json:"databaseSha256"`
	SchemaBefore        string            `json:"schemaBefore"`
	SchemaAfter         string            `json:"schemaAfter"`
	APIBefore           string            `json:"apiBefore"`
	APIAfter            string            `json:"apiAfter"`
	BootstrapSHA256     string            `json:"bootstrapSha256"`
	AdapterSHA256       map[string]string `json:"adapterSha256"`
}
type startupSnapshot struct {
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	API        string `json:"api"`
	UserPolicy string `json:"userPolicy"`
	Bootstrap  string `json:"bootstrap"`
}
type startupRecord struct {
	Attempt  string           `json:"attempt"`
	Manifest string           `json:"manifest"`
	State    string           `json:"state"`
	Before   *startupSnapshot `json:"before,omitempty"`
	After    *startupSnapshot `json:"after,omitempty"`
}
type ControlledStartup struct {
	manifest        StartupManifest
	record          startupRecord
	path            string
	serveInitialAPI string
}

func StartupServeWithoutDDL() bool { return startupMode == "serve-without-ddl" }
func startupDigest(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("cannot encode startup fingerprint")
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func startupExecutableDigest() (string, error) {
	name, err := os.Executable()
	if err != nil {
		return "", errors.New("cannot locate startup executable")
	}
	f, err := os.Open(name)
	if err != nil {
		return "", errors.New("cannot read startup executable")
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", errors.New("cannot hash startup executable")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func startupSyncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return errors.New("cannot open attempt directory")
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return errors.New("cannot sync attempt directory")
	}
	return nil
}

func readStartupFile(path string) ([]byte, error) {
	f, err := openStartupFile(path)
	if err != nil {
		return nil, errors.New("cannot open startup file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("startup file must be regular")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("cannot read bounded startup file")
	}
	return raw, nil
}

func startupConfigurationDigest() (string, error) {
	configuration := map[string]string{}
	for _, key := range []string{"CASDOOR_BUILTIN_ISOLATION_ENABLED", "CASDOOR_BUILTIN_ADMIN_IDS", "CASDOOR_BUILTIN_PROVISIONER_APPLICATION"} {
		configuration[key] = conf.GetConfigString(key)
	}
	// Match the actual passwordless-grant lookup, which has no config fallback.
	for _, key := range []string{"CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION"} {
		configuration[key] = os.Getenv(key)
	}
	on, mdl, row, err := migrationLockOptions("mysql")
	if err != nil {
		return "", err
	}
	configuration["CASDOOR_MIGRATION_LOCK_LIMITS_ENABLED"] = strconv.FormatBool(on)
	configuration["CASDOOR_MIGRATION_LOCK_WAIT_SECONDS"] = strconv.Itoa(mdl)
	configuration["CASDOOR_MIGRATION_INNODB_LOCK_WAIT_SECONDS"] = strconv.Itoa(row)
	return startupDigest(configuration), nil
}

func (g *ControlledStartup) validateCompletedRecord() error {
	r, m := g.record, g.manifest
	if r.State != "COMPLETED" || r.Attempt != startupAttemptID || r.Manifest != startupManifestSHA256 || r.Before == nil || r.After == nil {
		return errors.New("migration receipt not complete for exact attempt")
	}
	if r.Before.Database != m.DatabaseSHA256 || r.After.Database != m.DatabaseSHA256 ||
		r.Before.Schema != m.SchemaBefore || r.After.Schema != m.SchemaAfter ||
		r.Before.API != m.APIBefore || r.After.API != m.APIAfter ||
		r.Before.Bootstrap != m.BootstrapSHA256 || r.After.Bootstrap != m.BootstrapSHA256 ||
		!startupHex.MatchString(r.Before.UserPolicy) || r.Before.UserPolicy != r.After.UserPolicy {
		return errors.New("migration receipt fingerprints mismatch")
	}
	return nil
}

func BeginControlledStartup() (*ControlledStartup, error) {
	if startupMode == "" {
		return nil, nil
	}
	if startupMode != "migration-only" && !StartupServeWithoutDDL() {
		return nil, errors.New("invalid startup mode")
	}
	if createDatabase || exportData || conf.GetConfigString("initDataFile") != "" {
		return nil, errors.New("controlled startup forbids createDatabase, export and initDataFile")
	}
	if conf.GetConfigString("driverName") != "mysql" || conf.GetConfigString("tableNamePrefix") != "" {
		return nil, errors.New("controlled startup reviewed for MySQL without table prefix only")
	}
	if !startupHex.MatchString(startupManifestSHA256) || !startupName.MatchString(startupAttemptID) || !filepath.IsAbs(startupAttemptDirectory) {
		return nil, errors.New("invalid startup manifest or attempt input")
	}
	info, err := os.Lstat(startupAttemptDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("preexisting protected persistent attempt directory required")
	}
	resolved, err := filepath.EvalSymlinks(startupAttemptDirectory)
	if err != nil || resolved != filepath.Clean(startupAttemptDirectory) {
		return nil, errors.New("attempt directory must not resolve through symlinks")
	}
	bytes, err := readStartupFile(startupManifestPath)
	if err != nil {
		return nil, errors.New("cannot read bounded startup manifest")
	}
	h := sha256.Sum256(bytes)
	if hex.EncodeToString(h[:]) != startupManifestSHA256 {
		return nil, errors.New("startup manifest checksum mismatch")
	}
	var m StartupManifest
	if json.Unmarshal(bytes, &m) != nil || m.Version == "" || len(m.Version) > 64 {
		return nil, errors.New("invalid startup manifest")
	}
	for _, value := range []string{m.ConfigurationSHA256, m.BinarySHA256, m.DatabaseSHA256, m.SchemaBefore, m.SchemaAfter, m.APIBefore, m.APIAfter, m.BootstrapSHA256} {
		if !startupHex.MatchString(value) {
			return nil, errors.New("invalid startup fingerprint")
		}
	}
	configuration, err := startupConfigurationDigest()
	if err != nil {
		return nil, err
	}
	if configuration != m.ConfigurationSHA256 {
		return nil, errors.New("startup authority configuration mismatch")
	}
	// Resolve both real engine targets before creating the fence or opening DBs.
	if err := verifyStartupDatabaseTargets(m.DatabaseSHA256); err != nil {
		return nil, err
	}
	if len(m.AdapterSHA256) != 2 {
		return nil, errors.New("startup manifest requires exact two built-in adapters")
	}
	for _, id := range []string{"built-in/api-adapter-built-in", "built-in/user-adapter-built-in"} {
		if !startupHex.MatchString(m.AdapterSHA256[id]) {
			return nil, errors.New("invalid startup adapter binding")
		}
	}
	binary, err := startupExecutableDigest()
	if err != nil {
		return nil, err
	}
	if binary != m.BinarySHA256 {
		return nil, errors.New("startup binary checksum mismatch")
	}
	g := &ControlledStartup{manifest: m, path: filepath.Join(startupAttemptDirectory, "casdoor-startup-attempt.json")}
	if StartupServeWithoutDDL() {
		info, err = os.Lstat(g.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return nil, errors.New("protected completed migration receipt required")
		}
		raw, err := readStartupFile(g.path)
		if err != nil || json.Unmarshal(raw, &g.record) != nil {
			return nil, errors.New("invalid migration receipt")
		}
		if err = g.validateCompletedRecord(); err != nil {
			return nil, err
		}
	} else {
		on, _, _, err := migrationLockOptions("mysql")
		if err != nil || !on {
			return nil, errors.New("migration-only requires reviewed finite lock limits")
		}
		g.record = startupRecord{Attempt: startupAttemptID, Manifest: startupManifestSHA256, State: "STARTED"}
		// The one active fence is created before the first DB connection or DDL.
		// An existing STARTED, failed or completed fence is never overwritten here.
		f, err := os.OpenFile(g.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, errors.New("migration attempt already exists or fence unavailable; no retry")
		}
		raw, _ := json.Marshal(g.record)
		_, writeErr := f.Write(raw)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return nil, errors.New("migration fence persistence failed; inspect before any retry")
		}
		if err = startupSyncDirectory(startupAttemptDirectory); err != nil {
			return nil, err
		}
	}
	controlledStartup = g
	return g, nil
}

func startupAdapterDigest(a *Adapter) string {
	// Credentials are deliberately omitted; legitimate rotation does not alter target binding.
	return startupDigest(struct {
		ID, Table, Type, DatabaseType, Host, User, Database string
		Port                                                int
		UseSameDb                                           bool
	}{a.GetId(), a.Table, a.Type, a.DatabaseType, a.Host, a.User, a.Database, a.Port, a.UseSameDb})
}

func startupDatabaseDigest(driver, raw string) (string, error) {
	if driver != "mysql" {
		return "", errors.New("controlled startup requires MySQL target")
	}
	dsn, err := mysql.ParseDSN(raw)
	if err != nil || dsn.DBName == "" {
		return "", errors.New("cannot bind startup DB target")
	}
	return startupDigest(struct{ Driver, Net, Address, User, Database, Prefix string }{driver, dsn.Net, dsn.Addr, dsn.User, dsn.DBName, conf.GetConfigString("tableNamePrefix")}), nil
}

func validateControlledDatabaseTarget(driver, raw string) error {
	if controlledStartup == nil {
		return nil
	}
	hash, err := startupDatabaseDigest(driver, raw)
	if err != nil || hash != controlledStartup.manifest.DatabaseSHA256 {
		return errors.New("startup DB target mismatch before connection")
	}
	return nil
}

func verifyStartupDatabaseTargets(expected string) error {
	primary, err := migrationDataSourceName("mysql", conf.GetConfigDataSourceName(), conf.GetConfigString("dbName"), true)
	if err != nil {
		return err
	}
	adapter, err := migrationDataSourceName("mysql", conf.GetConfigString("dataSourceName"), conf.GetConfigString("dbName"), true)
	if err != nil {
		return err
	}
	adapter, err = resolveAdapterDataSourceName("mysql", adapter)
	if err != nil {
		return err
	}
	for _, raw := range []string{primary, adapter} {
		hash, err := startupDatabaseDigest("mysql", raw)
		if err != nil || hash != expected {
			return errors.New("startup DB targets mismatch before connection")
		}
	}
	return nil
}

func ValidateStartupAdapterBinding(a *Adapter) error {
	if controlledStartup == nil {
		return nil
	}
	expected, ok := controlledStartup.manifest.AdapterSHA256[a.GetId()]
	if !ok || !a.isBuiltIn() || !a.UseSameDb || !startupTable.MatchString(a.Table) || expected != startupAdapterDigest(a) {
		return errors.New("adapter outside reviewed startup binding")
	}
	return nil
}

func startupMetadata(query string) ([]map[string]string, error) {
	rows, err := ormer.Engine.QueryString(strings.Replace(query, "SELECT ", "SELECT /*+ MAX_EXECUTION_TIME(5000) */ ", 1) + " LIMIT 10001")
	if err != nil {
		return nil, errors.New("startup metadata read failed")
	}
	if len(rows) > 10000 {
		return nil, errors.New("startup metadata bound exceeded")
	}
	return rows, nil
}

func (g *ControlledStartup) snapshot() (*startupSnapshot, error) {
	resolved, err := migrationDataSourceName("mysql", conf.GetConfigDataSourceName(), conf.GetConfigString("dbName"), true)
	if err != nil {
		return nil, err
	}
	database, err := startupDatabaseDigest("mysql", resolved)
	if err != nil || database != g.manifest.DatabaseSHA256 {
		return nil, errors.New("startup DB target mismatch")
	}
	var schema []interface{}
	for _, q := range []string{
		"SELECT TABLE_NAME,ENGINE,TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY BINARY TABLE_NAME",
		"SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,COLUMN_TYPE,IS_NULLABLE,(COLUMN_DEFAULT IS NULL) AS DEFAULT_IS_NULL,COALESCE(COLUMN_DEFAULT,'') AS DEFAULT_VALUE,EXTRA,COALESCE(CHARACTER_SET_NAME,'') AS CHARSET_NAME,COALESCE(COLLATION_NAME,'') AS COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY BINARY TABLE_NAME,ORDINAL_POSITION",
		"SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COALESCE(COLUMN_NAME,'') AS COLUMN_NAME,COALESCE(SUB_PART,0) AS SUB_PART,COALESCE(COLLATION,'') AS COLLATION,INDEX_TYPE,COALESCE(EXPRESSION,'') AS EXPRESSION FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() ORDER BY BINARY TABLE_NAME,BINARY INDEX_NAME,SEQ_IN_INDEX",
	} {
		rows, err := startupMetadata(q)
		if err != nil {
			return nil, err
		}
		schema = append(schema, rows)
	}
	adapters, err := GetAdapters("built-in")
	if err != nil || len(adapters) != 2 {
		return nil, errors.New("startup adapter inventory mismatch")
	}
	var api, userPolicy string
	for _, a := range adapters {
		if err = ValidateStartupAdapterBinding(a); err != nil {
			return nil, err
		}
		q := "SELECT ptype,v0,v1,v2,v3,v4,v5 FROM `" + a.Table + "` ORDER BY BINARY ptype,BINARY v0,BINARY v1,BINARY v2,BINARY v3,BINARY v4,BINARY v5"
		rows, err := startupMetadata(q)
		if err != nil {
			return nil, err
		}
		if a.Name == "api-adapter-built-in" {
			api = startupDigest(rows)
		} else {
			userPolicy = startupDigest(rows)
		}
	}
	var bootstrap []interface{}
	for _, q := range []string{
		"SELECT owner,name,model_text FROM model WHERE owner='built-in' AND name IN ('api-model-built-in','user-model-built-in') ORDER BY BINARY name",
		"SELECT owner,name,model,adapter FROM enforcer WHERE owner='built-in' AND name IN ('api-enforcer-built-in','user-enforcer-built-in') ORDER BY BINARY name",
	} {
		rows, err := startupMetadata(q)
		if err != nil {
			return nil, err
		}
		if len(rows) != 2 {
			return nil, errors.New("missing existing startup model/enforcer")
		}
		bootstrap = append(bootstrap, rows)
	}
	return &startupSnapshot{Database: database, Schema: startupDigest(schema), API: api, UserPolicy: userPolicy, Bootstrap: startupDigest(bootstrap)}, nil
}

func (g *ControlledStartup) VerifyBefore() error {
	s, err := g.snapshot()
	if err != nil {
		return err
	}
	if s.Schema != g.manifest.SchemaBefore || s.API != g.manifest.APIBefore || s.Bootstrap != g.manifest.BootstrapSHA256 {
		return errors.New("migration preflight state mismatch")
	}
	g.record.Before = s
	return nil
}

func (g *ControlledStartup) VerifyServe() error {
	s, err := g.snapshot()
	if err != nil {
		return err
	}
	if s.Schema != g.manifest.SchemaAfter || s.Bootstrap != g.manifest.BootstrapSHA256 || g.record.After.Schema != s.Schema || g.record.After.Database != s.Database || g.record.After.Bootstrap != s.Bootstrap || g.record.After.API != g.manifest.APIAfter {
		return errors.New("runtime schema/version/migration receipt mismatch")
	}
	// COMPLETED records the immutable migration outcome; current API and user
	// policies are mutable DB-authoritative business data. Do not seed or bind
	// runtime API rows forever to the migration's default policy.
	g.serveInitialAPI = s.API
	return nil
}

func (g *ControlledStartup) CompleteMigration() error {
	s, err := g.snapshot()
	if err != nil {
		return err
	}
	if g.record.Before == nil || s.Schema != g.manifest.SchemaAfter || s.API != g.manifest.APIAfter || s.Bootstrap != g.manifest.BootstrapSHA256 || s.UserPolicy != g.record.Before.UserPolicy {
		return errors.New("migration final readback mismatch")
	}
	g.record.After = s
	g.record.State = "COMPLETED"
	f, err := os.CreateTemp(startupAttemptDirectory, ".startup-complete-")
	if err != nil {
		return errors.New("cannot stage migration receipt")
	}
	name := f.Name()
	defer os.Remove(name)
	raw, _ := json.Marshal(g.record)
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot persist migration receipt")
	}
	if err = os.Rename(name, g.path); err != nil {
		return errors.New("cannot commit migration receipt")
	}
	return startupSyncDirectory(startupAttemptDirectory)
}

// Check the loaded in-memory model too, closing the metadata/load race before HTTP.
func VerifyLoadedStartupAPIPolicy(e *casbin.Enforcer) error {
	if !StartupServeWithoutDDL() {
		return nil
	}
	if controlledStartup == nil || e == nil {
		return errors.New("missing controlled API policy")
	}
	rows := make([]map[string]string, 0)
	fields := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	for _, sec := range []string{"p", "g"} {
		for ptype, ast := range e.GetModel()[sec] {
			for _, rule := range ast.Policy {
				if len(rule) > 6 {
					return errors.New("API policy exceeds reviewed shape")
				}
				row := map[string]string{"ptype": ptype, "v0": "", "v1": "", "v2": "", "v3": "", "v4": "", "v5": ""}
				for i, value := range rule {
					row[fields[i+1]] = value
				}
				rows = append(rows, row)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		for _, k := range fields {
			if rows[i][k] != rows[j][k] {
				return rows[i][k] < rows[j][k]
			}
		}
		return false
	})
	if !startupHex.MatchString(controlledStartup.serveInitialAPI) || startupDigest(rows) != controlledStartup.serveInitialAPI {
		return errors.New("loaded API policy differs from startup DB snapshot")
	}
	// Catch a persistent policy/metadata change between snapshot and load.
	// No automatic re-read/retry, policy rewrite, privilege grant, or traffic.
	fresh, err := controlledStartup.snapshot()
	if err != nil {
		return err
	}
	if fresh.API != controlledStartup.serveInitialAPI || fresh.Schema != controlledStartup.manifest.SchemaAfter || fresh.Bootstrap != controlledStartup.manifest.BootstrapSHA256 {
		return errors.New("startup DB changed while loading API policy; stop and restart read-only preflight")
	}
	return nil
}
