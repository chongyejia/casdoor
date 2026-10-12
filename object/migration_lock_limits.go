// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"errors"
	"strconv"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/go-sql-driver/mysql"
)

// Migration limits belong in the DSN so new and replacement pool connections
// receive the same session limits before executing any statements.
func migrationLockOptions(driver string) (bool, int, int, error) {
	if driver != "mysql" {
		return false, 0, 0, nil
	}
	enabled := conf.GetConfigString("CASDOOR_MIGRATION_LOCK_LIMITS_ENABLED")
	if enabled == "" || enabled == "false" {
		return false, 0, 0, nil
	}
	if enabled != "true" {
		return false, 0, 0, errors.New("invalid migration lock enable flag")
	}
	seconds := func(key string) (int, error) {
		value := conf.GetConfigString(key)
		if value == "" {
			return 5, nil
		}
		if strings.Trim(value, "0123456789") != "" {
			return 0, errors.New("invalid migration lock seconds")
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 30 {
			return 0, errors.New("invalid migration lock seconds")
		}
		return n, nil
	}
	mdl, err := seconds("CASDOOR_MIGRATION_LOCK_WAIT_SECONDS")
	if err != nil {
		return false, 0, 0, err
	}
	row, err := seconds("CASDOOR_MIGRATION_INNODB_LOCK_WAIT_SECONDS")
	if err != nil {
		return false, 0, 0, err
	}
	return true, mdl, row, nil
}

// Off mode preserves the existing concatenation byte for byte. In migration
// mode, parse a prefix before assigning DBName so its query remains intact.
// Errors deliberately omit the DSN and driver diagnostics, which may contain secrets.
func migrationDataSourceName(driver, raw, database string, prefix bool) (string, error) {
	legacy := raw
	if prefix && driver == "mysql" {
		legacy += database
	}
	enabled, mdl, row, err := migrationLockOptions(driver)
	if err != nil {
		return "", err
	}
	if !enabled {
		return legacy, nil
	}
	cfg, err := mysql.ParseDSN(raw)
	if err != nil {
		return "", errors.New("invalid migration MySQL DSN")
	}
	if prefix {
		if cfg.DBName != "" || database == "" || strings.ContainsAny(database, "?/\\") {
			return "", errors.New("invalid migration database prefix")
		}
		cfg.DBName = database
	}
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["lock_wait_timeout"] = strconv.Itoa(mdl)
	cfg.Params["innodb_lock_wait_timeout"] = strconv.Itoa(row)
	return cfg.FormatDSN(), nil
}
