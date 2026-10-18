package routers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestBuiltinIsolationLegacySdkCreateObject(t *testing.T) {
	t.Setenv("CASDOOR_BUILTIN_ISOLATION_ENABLED", "true")
	for _, owner := range []string{"built-in", "other", ""} {
		body := `{"owner":"` + owner + `","name":"synthetic-user"}`
		ctx := context.NewContext()
		ctx.Reset(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/add-user?id=/synthetic-user", strings.NewReader(body)))
		ctx.Input.RequestBody = []byte(body)
		gotOwner, gotName, err := getObject(ctx)
		if err != nil || gotOwner != owner || gotName != "synthetic-user" {
			t.Fatal("body target must be authoritative, including missing/wrong owner")
		}
	}
}

func TestBuiltinIsolationAppTokenSession(t *testing.T) {
	t.Setenv("CASDOOR_BUILTIN_ISOLATION_ENABLED", "true")
	app := &object.Application{Organization: "built-in", Name: "app-built-in"}
	for _, user := range []string{"built-in/ordinary", "built-in/admin", "other/admin"} {
		if isClientSessionApiAllowed(app, user, "/api/update-provider") {
			t.Fatal("APP identity token became console authority")
		}
		if !isClientSessionApiAllowed(app, user, "/api/userinfo") {
			t.Fatal("identity endpoint denied")
		}
	}
	if !isCrossOrgClient(app, "other/admin") {
		t.Fatal("built-in application cross-org bypass")
	}
	t.Setenv("CASDOOR_BUILTIN_ISOLATION_ENABLED", "false")
	if isCrossOrgClient(app, "other/admin") {
		t.Fatal("off behavior changed")
	}
}

func TestBuiltinIsolationPreAuthPaths(t *testing.T) {
	for _, tt := range []struct {
		method string
		path   string
	}{
		{"GET", "/api/get-app-login"},
		{"GET", "/.well-known/openid-configuration"},
		{"GET", "/.well-known/petsengine-test/openid-configuration"},
		{"GET", "/.well-known/petsengine-test/jwks"},
		{"GET", "/api/webauthn/signin/begin"},
		{"POST", "/api/webauthn/signin/finish"},
		{"GET", "/api/webauthn/signup/begin"},
		{"POST", "/api/webauthn/signup/finish"},
		{"GET", "/api/webauthn/signin/begin-extra"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			ctx := context.NewContext()
			// A query parameter must not override the path used for isolation.
			ctx.Reset(httptest.NewRecorder(), httptest.NewRequest(tt.method, tt.path+"?detailPathUrl=/api/webauthn/signin/begin", nil))
			path := getUrlPath(ctx)
			extra := getExtraInfo(ctx, path)
			if strings.HasPrefix(tt.path, "/api/webauthn/") {
				if path != "/api/webauthn" {
					t.Fatalf("generic policy path = %q, want /api/webauthn", path)
				}
				if extra["detailPathUrl"] != tt.path {
					t.Errorf("isolation path = %v, want %q", extra["detailPathUrl"], tt.path)
				}
			} else if path != tt.path {
				t.Errorf("public path = %q, want %q", path, tt.path)
			}
		})
	}
}
