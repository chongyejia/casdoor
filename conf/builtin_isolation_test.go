package conf

import "testing"

func TestBuiltinIsolationConfig(t *testing.T) {
	for _, tc := range []struct {
		name, enabled, ids, app string
		valid                   bool
	}{
		{"default", "", "", "", true},
		{"off", "false", "", "", true},
		{"no admins", "true", "[]", "", false},
		{"bad json", "true", "admin", "", false},
		{"wildcard", "true", `["*"]`, "", false},
		{"name not id", "true", `["built-in/admin"]`, "", false},
		{"duplicate", "true", `["uuid-a","uuid-a"]`, "", false},
		{"invalid switch", "TRUE", `["uuid-a"]`, "", false},
		{"provision without isolation", "false", "", "admin/app-built-in", false},
		{"wrong application", "true", `["uuid-a"]`, "admin/other", false},
		{"valid isolation", "true", `["uuid-a"]`, "", true},
		{"valid provision", "true", `["uuid-a"]`, "admin/app-built-in", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CASDOOR_BUILTIN_ISOLATION_ENABLED", tc.enabled)
			t.Setenv("CASDOOR_BUILTIN_ADMIN_IDS", tc.ids)
			t.Setenv("CASDOOR_BUILTIN_PROVISIONER_APPLICATION", tc.app)
			if (ValidateBuiltinIsolationConfig() == nil) != tc.valid {
				t.Fatal("unexpected config validation")
			}
		})
	}
}
