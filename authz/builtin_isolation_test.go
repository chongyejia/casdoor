package authz

import "testing"

func TestBuiltinIsolationUserApi(t *testing.T) {
	for _, path := range []string{"/api/add-user", "/api/update-provider", "/api/get-providers", "/api/get-provider", "/api/get-users", "/api/add-role", "/api/update-permission", "/api/add-key", "/api/run-casbin-command", "/api/upload-users", "/api/impersonate-user", "/api/update-organization"} {
		for _, method := range []string{"GET", "POST"} {
			if builtinUserAPIAllowed("ordinary", method, path, "built-in", "ordinary") {
				t.Fatalf("management allowed: %s %s", method, path)
			}
		}
	}
	if !builtinUserAPIAllowed("ordinary", "GET", "/api/userinfo", "", "") {
		t.Fatal("identity denied")
	}
	if builtinUserAPIAllowed("ordinary", "POST", "/api/update-user", "built-in", "ordinary") {
		t.Fatal("general user mutation grants group/role-bearing fields")
	}
	if builtinUserAPIAllowed("ordinary", "POST", "/api/update-user", "built-in", "admin") {
		t.Fatal("other profile allowed")
	}
	if builtinUserAPIAllowed("ordinary", "POST", "/api/update-user", "other", "ordinary") {
		t.Fatal("cross organization allowed")
	}
}
