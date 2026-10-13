// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package xormadapter

import (
	"errors"

	"github.com/casbin/casbin/v2/model"
	"github.com/xorm-io/xorm"
)

// NewAdapterByEngineWithExistingTable opens an existing policy table. It never
// creates a database or synchronizes schema. The caller owns the engine.
func NewAdapterByEngineWithExistingTable(engine *xorm.Engine, tableName, tablePrefix string) (*Adapter, error) {
	if engine == nil || tableName == "" {
		return nil, errors.New("engine and explicit existing policy table required")
	}
	a := &Adapter{engine: engine, tableName: tableName, tablePrefix: tablePrefix}
	exists, err := engine.IsTableExist(&CasbinRule{tableName: a.getFullTableName()})
	if err != nil || !exists {
		return nil, errors.New("existing policy table unavailable")
	}
	return a, nil
}

// SavePolicyWithoutDDL replaces policies in one transaction, retaining the
// table, indexes and constraints. Like upstream SavePolicy, the caller must
// serialize policy writers. Incremental policy methods are unchanged.
func (a *Adapter) SavePolicyWithoutDDL(m model.Model) error {
	lines := make([]*CasbinRule, 0, 64)
	for _, sec := range []string{"p", "g"} {
		for ptype, ast := range m[sec] {
			for _, rule := range ast.Policy {
				if len(rule) > 6 {
					return errors.New("policy exceeds six persisted fields")
				}
				lines = append(lines, a.genPolicyLine(ptype, rule))
			}
		}
	}
	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		if _, err := tx.Where("1 = 1").Delete(&CasbinRule{tableName: a.getFullTableName()}); err != nil {
			return nil, err
		}
		if len(lines) > 0 {
			if _, err := tx.Insert(&lines); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}
