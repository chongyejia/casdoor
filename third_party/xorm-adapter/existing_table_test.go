// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package xormadapter

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/contexts"
	_ "modernc.org/sqlite"
)

type noDDLHook struct{ attempted int }

func (h *noDDLHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	q := strings.ToUpper(strings.TrimSpace(c.SQL))
	for _, verb := range []string{"CREATE ", "ALTER ", "DROP ", "TRUNCATE ", "RENAME "} {
		if strings.HasPrefix(q, verb) {
			h.attempted++
			return c.Ctx, errors.New("DDL forbidden by test guard")
		}
	}
	return c.Ctx, nil
}
func (h *noDDLHook) AfterProcess(c *contexts.ContextHook) error { return c.Err }

func existingEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	e, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	e.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func existingFixture(t *testing.T) (*xorm.Engine, *Adapter, []map[string]string) {
	t.Helper()
	e := existingEngine(t)
	for _, table := range []string{"bound_rules", "untouched_rules"} {
		if _, err := NewAdapterByEngineWithTableName(e, table, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Exec("INSERT INTO " + table + "(ptype,v0,v1,v2) VALUES ('p','original','resource','read')"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Exec("CREATE UNIQUE INDEX sentinel_preserved ON bound_rules(ptype,v0,v1,v2,v3,v4,v5)"); err != nil {
		t.Fatal(err)
	}
	before := schemaRows(t, e)
	h := &noDDLHook{}
	e.AddHook(h)
	t.Cleanup(func() {
		if h.attempted != 0 {
			t.Errorf("attempted %d forbidden DDL statements", h.attempted)
		}
	})
	a, err := NewAdapterByEngineWithExistingTable(e, "rules", "bound_")
	if err != nil {
		t.Fatal(err)
	}
	return e, a, before
}

func schemaRows(t *testing.T, e *xorm.Engine) []map[string]string {
	t.Helper()
	rows, err := e.QueryString("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func policyRows(t *testing.T, e *xorm.Engine, table string) []map[string]string {
	t.Helper()
	rows, err := e.QueryString("SELECT ptype,v0,v1,v2,v3,v4,v5 FROM " + table + " ORDER BY ptype,v0,v1,v2,v3,v4,v5")
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func testPolicy(t *testing.T) model.Model {
	t.Helper()
	m, err := model.NewModelFromString("[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n[role_definition]\ng = _, _\n[policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act\n")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExistingTableRejectsMissingWithoutDDL(t *testing.T) {
	e := existingEngine(t)
	h := &noDDLHook{}
	e.AddHook(h)
	for _, table := range []string{"", "missing"} {
		if _, err := NewAdapterByEngineWithExistingTable(e, table, ""); err == nil {
			t.Fatal("missing explicit table accepted")
		}
	}
	if _, err := NewAdapterByEngineWithExistingTable(nil, "missing", ""); err == nil {
		t.Fatal("nil engine accepted")
	}
	if h.attempted != 0 || len(schemaRows(t, e)) != 0 {
		t.Fatal("constructor attempted schema creation")
	}
}

func TestExistingTableSaveAndClearPreserveSchema(t *testing.T) {
	e, a, schema := existingFixture(t)
	other := policyRows(t, e, "untouched_rules")
	m := testPolicy(t)
	m.AddPolicy("p", "p", []string{"operator", "resource", "write"})
	m.AddPolicy("g", "g", []string{"person", "operator"})
	if err := a.SavePolicyWithoutDDL(m); err != nil {
		t.Fatal(err)
	}
	loaded := testPolicy(t)
	if err := a.LoadPolicy(loaded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m["p"]["p"].Policy, loaded["p"]["p"].Policy) || !reflect.DeepEqual(m["g"]["g"].Policy, loaded["g"]["g"].Policy) {
		t.Fatal("policy roundtrip differs")
	}
	if err := a.SavePolicyWithoutDDL(testPolicy(t)); err != nil {
		t.Fatal(err)
	}
	if len(policyRows(t, e, "bound_rules")) != 0 || !reflect.DeepEqual(schema, schemaRows(t, e)) || !reflect.DeepEqual(other, policyRows(t, e, "untouched_rules")) {
		t.Fatal("bulk save changed schema/other table or failed to clear")
	}
}

func TestExistingTableInsertFailureRollsBackDelete(t *testing.T) {
	e, a, schema := existingFixture(t)
	before := policyRows(t, e, "bound_rules")
	m := testPolicy(t)
	// Deliberately invalid duplicate input reaches the real database constraint.
	m["p"]["p"].Policy = [][]string{{"duplicate", "resource", "read"}, {"duplicate", "resource", "read"}}
	if err := a.SavePolicyWithoutDDL(m); err == nil {
		t.Fatal("duplicate constraint should fail")
	}
	if !reflect.DeepEqual(before, policyRows(t, e, "bound_rules")) || !reflect.DeepEqual(schema, schemaRows(t, e)) {
		t.Fatal("failed insertion did not restore original policy/schema")
	}
}

func TestExistingTableDeleteFailurePreservesPolicy(t *testing.T) {
	e := existingEngine(t)
	if _, err := NewAdapterByEngineWithTableName(e, "bound_rules", ""); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{"INSERT INTO bound_rules(ptype,v0) VALUES ('p','original')", "CREATE TRIGGER deny_delete BEFORE DELETE ON bound_rules BEGIN SELECT RAISE(ABORT, 'synthetic delete denial'); END"} {
		if _, err := e.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	before, schema := policyRows(t, e, "bound_rules"), schemaRows(t, e)
	h := &noDDLHook{}
	e.AddHook(h)
	a, err := NewAdapterByEngineWithExistingTable(e, "bound_rules", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SavePolicyWithoutDDL(testPolicy(t)); err == nil {
		t.Fatal("delete trigger should fail")
	}
	if h.attempted != 0 || !reflect.DeepEqual(before, policyRows(t, e, "bound_rules")) || !reflect.DeepEqual(schema, schemaRows(t, e)) {
		t.Fatal("failed deletion changed policy/schema")
	}
}

func TestExistingTableOversizedPolicyFailsBeforeDelete(t *testing.T) {
	e, a, schema := existingFixture(t)
	before := policyRows(t, e, "bound_rules")
	m := testPolicy(t)
	m["p"]["p"].Policy = [][]string{{"a", "b", "c", "d", "e", "f", "g"}}
	if err := a.SavePolicyWithoutDDL(m); err == nil {
		t.Fatal("policy would be silently truncated")
	}
	if !reflect.DeepEqual(before, policyRows(t, e, "bound_rules")) || !reflect.DeepEqual(schema, schemaRows(t, e)) {
		t.Fatal("invalid policy changed data/schema")
	}
}
