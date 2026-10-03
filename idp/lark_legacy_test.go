package idp

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type larkRoundTrip func(*http.Request) (*http.Response, error)

func (f larkRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestLegacyLarkExplicitIDSelection(t *testing.T) {
	for _, tc := range []struct{ kind, want string }{
		{"user_id", "user-synthetic"},
		{"union_id", "union-synthetic"},
		{"open_id", "open-synthetic"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			provider := NewLarkIdProvider("test-app", "test-secret", "", false, tc.kind)
			provider.SetHttpClient(&http.Client{Transport: larkRoundTrip(func(req *http.Request) (*http.Response, error) {
				var body string
				switch req.URL.Path {
				case "/open-apis/authen/v1/oidc/access_token":
					if req.Header.Get("Authorization") != "Bearer synthetic-app-token" {
						t.Fatal("wrong app token")
					}
					body = `{"code":0,"data":{"access_token":"synthetic-user-token"}}`
				case "/open-apis/authen/v1/user_info":
					if req.Header.Get("Authorization") != "Bearer synthetic-user-token" {
						t.Fatal("wrong user token")
					}
					body = `{"code":0,"data":{"name":"Synthetic","user_id":"user-synthetic","union_id":"union-synthetic","open_id":"open-synthetic","enterprise_email":"synthetic@example.invalid","tenant_key":"tenant-A"}}`
				default:
					t.Fatalf("unexpected endpoint: %s", req.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})})
			info, err := provider.GetUserInfo((&oauth2.Token{AccessToken: "synthetic-app-token"}).WithExtra(map[string]interface{}{"code": "synthetic-code"}))
			if err != nil {
				t.Fatal(err)
			}
			if info.Id != tc.want || info.Username != "lark-"+tc.want || info.Extra["larkIdType"] != tc.kind {
				t.Fatalf("wrong explicit identity: %+v", info)
			}
			if info.EmailVerified || info.PhoneVerified {
				t.Fatal("Lark response did not prove email or phone ownership")
			}
		})
	}
}

func TestLegacyLarkRejectsMissingSelectedID(t *testing.T) {
	provider := NewLarkIdProvider("test-app", "test-secret", "", false, "user_id")
	provider.SetHttpClient(&http.Client{Transport: larkRoundTrip(func(req *http.Request) (*http.Response, error) {
		body := `{"code":0,"data":{"access_token":"synthetic-user-token"}}`
		if strings.HasSuffix(req.URL.Path, "/user_info") {
			body = `{"code":0,"data":{"open_id":"other-type-only"}}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})})
	if _, err := provider.GetUserInfo((&oauth2.Token{AccessToken: "synthetic-app-token"}).WithExtra(map[string]interface{}{"code": "synthetic-code"})); err == nil {
		t.Fatal("missing configured user_id must not fall back to open_id")
	}
}

func TestLegacyLarkRejectsUnconfiguredIDType(t *testing.T) {
	if _, err := GetIdProvider(&ProviderInfo{Type: "Lark", ClientId: "synthetic"}, ""); err == nil {
		t.Fatal("unconfigured ID type must not use upstream fallback")
	}
}

func TestLegacyLarkUsesAppTokenEndpoint(t *testing.T) {
	provider := NewLarkIdProvider("synthetic-app", "synthetic-secret", "", false, "user_id")
	provider.SetHttpClient(&http.Client{Transport: larkRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/open-apis/auth/v3/app_access_token/internal" {
			t.Fatalf("wrong legacy app token endpoint: %s", req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"code":0,"app_access_token":"synthetic-app-token","expire":3600}`)), Header: http.Header{}}, nil
	})})
	token, err := provider.GetToken("synthetic-code")
	if err != nil || token.AccessToken != "synthetic-app-token" || token.Extra("code") != "synthetic-code" {
		t.Fatalf("legacy app token: token=%+v, error=%v", token, err)
	}
}

func TestLegacyLarkRejectsInvalidAppTokenResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"HTTP failure", http.StatusForbidden, `{"code":0,"app_access_token":"synthetic-app-token","expire":3600}`},
		{"missing code", http.StatusOK, `{"app_access_token":"synthetic-app-token","expire":3600}`},
		{"expired token", http.StatusOK, `{"code":0,"app_access_token":"synthetic-app-token","expire":0}`},
		{"provider error", http.StatusOK, `{"code":999,"app_access_token":"synthetic-app-token","expire":3600}`},
		{"malformed JSON", http.StatusOK, `{invalid`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := NewLarkIdProvider("synthetic-app", "synthetic-secret", "", false, "user_id")
			provider.SetHttpClient(&http.Client{Transport: larkRoundTrip(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{}}, nil
			})})
			if _, err := provider.GetToken("synthetic-code"); err == nil {
				t.Fatal("invalid app token response accepted")
			}
		})
	}
}
