// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xorm-io/xorm"
)

func TestControlledRuntimeExistingAnchorsNoSeed(t *testing.T) {
	cases := []struct{ name, omit, wrongOwner, want string }{
		{"complete", "", "", ""},
		{"missing-organization", "organization", "", "existing built-in organization required"},
		{"wrong-organization-owner", "", "other", "existing built-in organization required"},
		{"missing-api-model", "api-model-built-in", "", "existing startup model required"},
		{"missing-user-model", "user-model-built-in", "", "existing startup model required"},
		{"missing-api-enforcer", "api-enforcer-built-in", "", "existing startup enforcer required"},
		{"missing-user-enforcer", "user-enforcer-built-in", "", "existing startup enforcer required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := xorm.NewEngine("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			engine.SetMaxOpenConns(1)
			previous := ormer
			ormer = &Ormer{driverName: "sqlite", Engine: engine}
			t.Cleanup(func() { ormer = previous; engine.Close() })
			if err = engine.Sync2(new(Organization), new(Model), new(Enforcer)); err != nil {
				t.Fatal(err)
			}
			if tc.omit != "organization" {
				owner := "admin"
				if tc.wrongOwner != "" {
					owner = tc.wrongOwner
				}
				if _, err = engine.Insert(&Organization{Owner: owner, Name: "built-in"}); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"api-model-built-in", "user-model-built-in"} {
				if tc.omit == name {
					continue
				}
				if _, err = engine.Insert(&Model{Owner: "built-in", Name: name}); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"api-enforcer-built-in", "user-enforcer-built-in"} {
				if tc.omit == name {
					continue
				}
				if _, err = engine.Insert(&Enforcer{Owner: "built-in", Name: name}); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				data := make(map[string]interface{})
				for _, table := range []string{"organization", "model", "enforcer"} {
					rows, e := engine.QueryString("SELECT * FROM " + table + " ORDER BY owner,name")
					if e != nil {
						t.Fatal(e)
					}
					data[table] = rows
				}
				schema, e := engine.QueryString("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
				if e != nil {
					t.Fatal(e)
				}
				data["schema"] = schema
				b, e := json.Marshal(data)
				if e != nil {
					t.Fatal(e)
				}
				return string(b)
			}
			before := snapshot()
			if _, err = engine.Exec("PRAGMA query_only = ON"); err != nil {
				t.Fatal(err)
			}
			err = InitRuntimeExistingDb()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("existing canonical anchors rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if after := snapshot(); after != before {
				t.Fatal("existing anchors or schema changed")
			}
		})
	}
}
