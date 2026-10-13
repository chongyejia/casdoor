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
