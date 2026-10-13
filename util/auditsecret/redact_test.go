package auditsecret

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"strings"
	"testing"
)

func TestSupportedBodies(t *testing.T) {
	var multipartBody bytes.Buffer
	w := multipart.NewWriter(&multipartBody)
	for _, field := range []struct{ key, value string }{
		{"userOwner", "petsengine"}, {"oldPassword", "synthetic-old"},
		{"newPassword", "synthetic-new"}, {"newPassword", "synthetic-repeat"},
		{"confirm_password", "synthetic-confirm"},
	} {
		if err := w.WriteField(field.key, field.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, body, contentType string }{
		{"json", `{"userOwner":"petsengine","password":"synthetic-old","nested":[{"NEW_PASSWORD":"synthetic-new"}],"confirmPassword":"synthetic-confirm","number":9007199254740993}`, "application/json; charset=utf-8"},
		{"form", "userOwner=petsengine&oldPassword=synthetic-old&newPassword=synthetic-new&newPassword=synthetic-repeat&confirm_password=synthetic-confirm", "application/x-www-form-urlencoded"},
		{"multipart", multipartBody.String(), w.FormDataContentType()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Body(test.body, test.contentType)
			if strings.Contains(result, "synthetic-") {
				t.Fatalf("secret retained")
			}
			if !strings.Contains(result, "petsengine") || !strings.Contains(result, Mask) {
				t.Fatalf("metadata or masking missing: %s", result)
			}
			if !json.Valid([]byte(result)) {
				t.Fatal("invalid audit JSON")
			}
			if second := Body(result, "application/json"); second != result {
				t.Fatal("defensive pass changed metadata")
			}
			if test.name == "json" && !strings.Contains(result, "9007199254740993") {
				t.Fatal("numeric metadata lost precision")
			}
		})
	}
}

func TestMalformedBodiesFailClosed(t *testing.T) {
	for _, test := range []struct{ body, contentType string }{
		{`{"newPassword":"synthetic-new"`, "application/json"},
		{`{"newPassword":"synthetic-new"} {}`, "application/json"},
		{"newPassword=synthetic-new&bad=%zz", "application/x-www-form-urlencoded"},
		{"synthetic-new", "multipart/form-data"},
		{"--wrong\r\nsynthetic-new", "multipart/form-data; boundary=expected"},
		{"synthetic-new", "text/plain"},
		{"synthetic-new", "application/json; broken"},
		{`"synthetic-new"`, "application/json"},
		{"null", "application/json"},
	} {
		if result := Body(test.body, test.contentType); result != Omitted {
			t.Fatalf("malformed request was not omitted: %s", result)
		}
	}
	if Body("", "") != "" {
		t.Fatal("empty body changed")
	}
}

func TestNewCasdoorCredentialsAndEncodedNames(t *testing.T) {
	for _, key := range []string{"accessSecret", "code_verifier", "passcode", "recoveryCode", "id_token_hint", "newPasswor\\u0064"} {
		body := `{"` + key + `":"synthetic-secret","id":"stable-id"}`
		result := Body(body, "application/json")
		if strings.Contains(result, "synthetic-secret") || !strings.Contains(result, "stable-id") {
			t.Fatalf("credential masking or stable metadata failed for %s", key)
		}
	}
	result := Body("new%50assword=synthetic-secret&userOwner=built-in", "application/x-www-form-urlencoded")
	if strings.Contains(result, "synthetic-secret") || !strings.Contains(result, "built-in") {
		t.Fatal("encoded form field was not masked")
	}
}

func TestURI(t *testing.T) {
	raw := "/api/set-password?userOwner=petsengine&clientSecret=synthetic-client&access_token=synthetic-token&%6eewPassword=synthetic-new&newPassword=synthetic-repeat"
	result := URI(raw)
	if strings.Contains(result, "synthetic-") || !strings.Contains(result, "userOwner=petsengine") {
		t.Fatal("URI redaction failed")
	}
	if URI(result) != result {
		t.Fatal("URI masking is not idempotent")
	}
	if strings.Contains(URI("/api/set-password?newPassword=synthetic-new&bad=%zz"), "synthetic-") {
		t.Fatal("malformed query leaked")
	}
}

func TestOtherCredentialAliases(t *testing.T) {
	result := Body(`{"passwd":"synthetic-a","pwd":"synthetic-b","client-secret":"synthetic-c","accessToken":"synthetic-d","refresh_token":"synthetic-e","authorization":"synthetic-f","%6eewPassword":"synthetic-g","unchanged":"public"}`, "application/json")
	if strings.Contains(result, "synthetic-") || !strings.Contains(result, "public") {
		t.Fatal("alias redaction failed")
	}
}
