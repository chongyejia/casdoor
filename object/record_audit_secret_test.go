package object

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/util/auditsecret"
)

func TestAuditRecordEncodedCredentials(t *testing.T) {
	for _, tc := range []struct{ name, contentType, body string }{
		{"form", "application/x-www-form-urlencoded", "new%50assword=synthetic-secret&userOwner=petsengine"},
		{"json", "application/json", `{"newPasswor\u0064":"synthetic-secret","userOwner":"petsengine","nested":[{"accessSecret":"synthetic-secret"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/set-password?userOwner=petsengine&id_token_hint=synthetic-secret", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			ctx := context.NewContext()
			ctx.Reset(httptest.NewRecorder(), r)
			ctx.Input.RequestBody = []byte(tc.body)
			ctx.Input.SetData("json", Response{Status: "ok", Data: "synthetic-secret"})
			record, err := NewRecord(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(record.Object+record.RequestUri+record.Response, "synthetic-secret") {
				t.Fatal("credential survived record construction")
			}
			if !strings.Contains(record.Object, "petsengine") || record.Action != "set-password" {
				t.Fatal("audit context lost")
			}
			if maskSecrets(record.Object) != record.Object {
				t.Fatal("pre-webhook defensive pass is not idempotent")
			}
		})
	}
}

func TestAuditRecordMalformedBody(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/set-password", nil)
	r.Header.Set("Content-Type", "application/json")
	ctx := context.NewContext()
	ctx.Reset(httptest.NewRecorder(), r)
	ctx.Input.RequestBody = []byte(`{"newPassword":"synthetic-secret"`)
	ctx.Input.SetData("json", Response{Status: "error"})
	record, err := NewRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if record.Object != auditsecret.Omitted {
		t.Fatal("malformed body was retained")
	}
}
