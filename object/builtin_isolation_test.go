package object

import (
	"encoding/json"
	"testing"
)

func builtinIsolationTestConfig(t *testing.T) {
	t.Helper()
	t.Setenv("CASDOOR_BUILTIN_ISOLATION_ENABLED", "true")
	t.Setenv("CASDOOR_BUILTIN_ADMIN_IDS", `["stable-admin-id"]`)
	t.Setenv("CASDOOR_BUILTIN_PROVISIONER_APPLICATION", "admin/app-built-in")
}

func TestBuiltinIsolationAdministratorBoundary(t *testing.T) {
	builtinIsolationTestConfig(t)
	for _, tc := range []struct {
		name        string
		user        *User
		global, org bool
	}{
		{"nil", nil, false, false},
		{"ordinary", &User{Owner: "built-in", Name: "ordinary", Id: "stable-ordinary"}, false, false},
		{"legacy is_admin", &User{Owner: "built-in", IsAdmin: true}, false, false},
		{"admin name only", &User{Owner: "built-in", Name: "admin"}, false, false},
		{"explicit id", &User{Owner: "built-in", Id: "stable-admin-id"}, true, false},
		{"wrong owner", &User{Owner: "other", Id: "stable-admin-id"}, false, false},
		{"disabled admin", &User{Owner: "built-in", Id: "stable-admin-id", IsForbidden: true}, false, false},
		{"deleted admin", &User{Owner: "built-in", Id: "stable-admin-id", IsDeleted: true}, false, false},
		{"ordinary org admin", &User{Owner: "cyj-inner", IsAdmin: true}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.user.IsGlobalAdmin() != tc.global || tc.user.IsOrganizationAdmin() != tc.org {
				t.Fatal("unexpected authority")
			}
		})
	}
	var forged User
	_ = json.Unmarshal([]byte(`{"owner":"built-in","name":"app/app-built-in","isAdmin":true,"builtinServiceIdentity":true}`), &forged)
	if forged.IsAdminUser() {
		t.Fatal("JSON forged service capability")
	}
	if mayUseOrganizationMasterPassword(&User{Owner: "built-in", Id: "stable-admin-id"}) {
		t.Fatal("organization master password must not impersonate console administrator")
	}
	if !mayUseOrganizationMasterPassword(&User{Owner: "built-in", Id: "ordinary"}) {
		t.Fatal("ordinary passwordless APP compatibility must remain available")
	}
	t.Setenv("CASDOOR_BUILTIN_ISOLATION_ENABLED", "false")
	if !(&User{Owner: "built-in"}).IsGlobalAdmin() {
		t.Fatal("default-off legacy behavior changed")
	}
}

func TestBuiltinIsolationProvisioningPayload(t *testing.T) {
	builtinIsolationTestConfig(t)
	app := &Application{Owner: "admin", Name: "app-built-in", Organization: "built-in"}
	valid := User{Owner: "built-in", Name: "synthetic-user", SignupApplication: "app-built-in", Tag: "staff", Properties: map[string]string{"registerPlatform": "snailpet"}}
	if err := ValidateBuiltinProvisionedUser(app, &valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*User){
		func(u *User) { u.IsAdmin = true }, func(u *User) { u.Id = "stable-admin-id" }, func(u *User) { u.Owner = "other" },
		func(u *User) { u.Name = "admin" }, func(u *User) { u.Name = "app/forged" }, func(u *User) { u.Password = "secret" },
		func(u *User) { u.Tag = "administrator" }, func(u *User) { u.AccessToken = "token" },
		func(u *User) { u.Groups = []string{"built-in/admin"} }, func(u *User) { u.Properties = map[string]string{"isAdmin": "true"} },
	} {
		u := valid
		mutate(&u)
		if ValidateBuiltinProvisionedUser(app, &u) == nil {
			t.Fatal("authority payload accepted")
		}
	}
	for _, mutate := range []func(*Application){func(a *Application) { a.Owner = "other" }, func(a *Application) { a.Name = "other" }, func(a *Application) { a.Organization = "other" }, func(a *Application) { a.IsShared = true }, func(a *Application) { a.Tags = []string{"dcr"} }, func(a *Application) { a.DisableSignin = true }} {
		a := *app
		mutate(&a)
		if ValidateBuiltinProvisionedUser(&a, &valid) == nil {
			t.Fatal("wrong application accepted")
		}
	}
}

func TestBuiltinIsolationProfileUpdate(t *testing.T) {
	builtinIsolationTestConfig(t)
	old := User{Owner: "built-in", Name: "ordinary", Id: "ordinary-stable", Phone: "synthetic-old", CountryCode: "US"}
	next := old
	next.Phone = "synthetic-new"
	next.CountryCode = "CN"
	if err := ValidateBuiltinServiceUserUpdate(&old, &next, "phone,country_code"); err != nil {
		t.Fatal(err)
	}
	next.IsAdmin = true
	next.DeletedTime = "malicious"
	next.Password = "malicious"
	projected, err := PrepareBuiltinServiceUserUpdate(&old, &next, "phone,country_code")
	if err != nil || projected.IsAdmin || projected.DeletedTime != "" || projected.Password != old.Password || projected.Phone != next.Phone {
		t.Fatal("unselected fields reached derived update logic")
	}
	for _, col := range []string{"", "is_admin", "roles", "owner", "name", "id", "password", "phone,is_admin"} {
		if ValidateBuiltinServiceUserUpdate(&old, &next, col) == nil {
			t.Fatalf("accepted column %s", col)
		}
	}
	next.ExternalId = old.Id
	if err := ValidateBuiltinServiceUserUpdate(&old, &next, "external_id"); err != nil {
		t.Fatal(err)
	}
	old.ExternalId = "legacy-business-id"
	if ValidateBuiltinServiceUserUpdate(&old, &next, "external_id") == nil {
		t.Fatal("legacy ID overwrite accepted")
	}
	old.Id = "stable-admin-id"
	next = old
	next.Phone = "changed"
	if ValidateBuiltinServiceUserUpdate(&old, &next, "phone") == nil {
		t.Fatal("administrator update accepted")
	}
}
