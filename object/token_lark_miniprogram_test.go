package object

import (
	"testing"

	"github.com/casdoor/casdoor/idp"
)

func TestLarkMiniProgramRejectsMissingProviderCodeAndIDType(t *testing.T) {
	app := &Application{Organization: "synthetic-owner"}
	if _, tokenError, err := GetLarkMiniProgramToken(app, "synthetic-code", "", "", "", "en", "198.51.100.7"); err != nil || tokenError == nil || tokenError.Error != InvalidClient {
		t.Fatalf("missing provider: error=%v tokenError=%+v", err, tokenError)
	}
	app.Providers = []*ProviderItem{{Provider: &Provider{Owner: "synthetic-owner", Name: "synthetic-lark", Type: "LarkMiniProgram"}}}
	if _, tokenError, err := GetLarkMiniProgramToken(app, "", "", "", "", "en", "198.51.100.7"); err != nil || tokenError == nil || tokenError.Error != InvalidRequest {
		t.Fatalf("missing code: error=%v tokenError=%+v", err, tokenError)
	}
	if _, tokenError, err := GetLarkMiniProgramToken(app, "synthetic-code", "", "", "", "en", "198.51.100.7"); err != nil || tokenError == nil || tokenError.Error != InvalidRequest {
		t.Fatalf("missing ID type: error=%v tokenError=%+v", err, tokenError)
	}
}

func TestLarkMiniProgramRejectsAmbiguousProviders(t *testing.T) {
	app := &Application{Organization: "synthetic-owner", Providers: []*ProviderItem{
		{Provider: &Provider{Owner: "synthetic-owner", Name: "one", Type: "LarkMiniProgram", UserIdType: "user_id"}},
		{Provider: &Provider{Owner: "synthetic-owner", Name: "two", Type: "LarkMiniProgram", UserIdType: "user_id"}},
	}}
	if GetLarkMiniProgramProvider(app) != nil {
		t.Fatal("a tag without provider identity cannot select between two providers")
	}
	if _, tokenError, err := GetLarkMiniProgramToken(app, "synthetic-code", "", "", "", "en", "198.51.100.7"); err != nil || tokenError == nil || tokenError.Error != InvalidClient {
		t.Fatalf("ambiguous providers: error=%v tokenError=%+v", err, tokenError)
	}
}

func TestLarkMiniProgramRejectsMismatchedSelectedIDBeforeLookup(t *testing.T) {
	app := &Application{Organization: "synthetic-owner"}
	info := &idp.UserInfo{Id: "synthetic-user", Extra: map[string]string{"larkOpenId": "synthetic-open"}}
	if _, tokenError, err := getLarkMiniProgramTokenForIdentity(app, &ProviderItem{CanSignIn: true}, "user_id", info, "", "198.51.100.7", "en"); err != nil || tokenError == nil || tokenError.Error != InvalidRequest {
		t.Fatalf("wrong ID type must stop before account lookup: error=%v tokenError=%+v", err, tokenError)
	}
}
