package authz

import "testing"

func TestBuiltinIsolationUserApi(t *testing.T) {
	for _, path := range []string{"/api/add-user", "/api/update-provider", "/api/get-providers", "/api/get-users", "/api/add-role", "/api/update-permission", "/api/add-key", "/api/run-casbin-command", "/api/upload-users", "/api/impersonate-user", "/api/update-organization", "/api/get-organizations", "/api/get-applications", "/api/get-all-roles", "/api/get-all-objects", "/api/get-all-actions", "/api/get-resources", "/api/get-records", "/api/get-orders", "/api/get-products", "/api/update-user", "/api/add-application", "/api/get-idp-discovery", "/api/webauthn", "/api/webauthn/signup/begin", "/api/webauthn/signup/finish", "/api/webauthn/signin/begin-extra", "/api/webauthn/signin/finish-extra"} {
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

func TestBuiltinIsolationPublicPreAuthAPIs(t *testing.T) {
	for _, tt := range []struct {
		method string
		path   string
	}{
		{"GET", "/api/get-app-login"},
		{"GET", "/api/get-captcha"},
		{"GET", "/api/get-captcha-status"},
		{"GET", "/api/get-email-and-phone"},
		{"GET", "/api/get-organization-names"},
		{"GET", "/api/get-saml-login"},
		{"GET", "/api/get-invitation-info"},
		{"GET", "/api/get-qrcode"},
		{"GET", "/api/get-webhook-event"},
		{"GET", "/api/faceid-signin-begin"},
		{"GET", "/api/kerberos-login"},
		{"GET", "/api/get-provider"},
		{"GET", "/api/saml/metadata"},
		{"GET", "/api/webauthn/signin/begin"},
		{"POST", "/api/webauthn/signin/finish"},
		{"GET", "/.well-known/openid-configuration"},
		{"GET", "/.well-known/oauth-authorization-server"},
		{"GET", "/.well-known/oauth-protected-resource"},
		{"GET", "/.well-known/webfinger"},
		{"GET", "/.well-known/jwks"},
		{"GET", "/.well-known/petsengine-test/openid-configuration"},
		{"GET", "/.well-known/petsengine-test/oauth-authorization-server"},
		{"GET", "/.well-known/petsengine-test/oauth-protected-resource"},
		{"GET", "/.well-known/petsengine-test/webfinger"},
		{"GET", "/.well-known/petsengine-test/jwks"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} {
				want := method == tt.method
				if got := builtinUserAPIAllowed("ordinary", method, tt.path, "", ""); got != want {
					t.Errorf("builtinUserAPIAllowed(%s, %s) = %v, want %v", method, tt.path, got, want)
				}
			}
		})
	}
}

func TestBuiltinIsolationDiscoveryPathBoundary(t *testing.T) {
	for _, path := range []string{"/.well-known", "/.well-known-evil/openid-configuration", "/api/.well-known/openid-configuration", "/api/get-app-login-extra"} {
		t.Run(path, func(t *testing.T) {
			if builtinUserAPIAllowed("ordinary", "GET", path, "", "") {
				t.Fatal("non-public path allowed")
			}
		})
	}
}
