package object

import (
	"testing"

	"github.com/xorm-io/xorm"
)

func TestTokenLookupIDSessionHints(t *testing.T) {
	engine, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMaxOpenConns(1)
	if err := engine.Sync2(new(Token)); err != nil {
		engine.Close()
		t.Fatal(err)
	}
	previous := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: engine}
	t.Cleanup(func() { ormer = previous; engine.Close() })
	row := &Token{Owner: "synthetic-owner", Name: "synthetic-session", Organization: "synthetic-org", User: "synthetic-user", AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", IdToken: "synthetic-id", ExpiresIn: 3600}
	if ok, err := AddToken(row); err != nil || !ok {
		t.Fatalf("insert: ok=%v err=%v", ok, err)
	}
	for _, hint := range []string{"id_token", "id-token", "urn:ietf:params:oauth:token-type:id_token"} {
		t.Run(hint, func(t *testing.T) {
			found, err := GetTokenByTokenValue("synthetic-id", hint)
			if err != nil || found == nil || found.GetId() != row.GetId() {
				t.Fatalf("ID session not found: %v", err)
			}
			wrong, err := GetTokenByTokenValue("synthetic-access", hint)
			if err != nil || wrong != nil {
				t.Fatal("ID hint accepted access value")
			}
		})
	}
	for _, pair := range [][2]string{{"access_token", "synthetic-access"}, {"access-token", "synthetic-access"}, {"refresh_token", "synthetic-refresh"}, {"refresh-token", "synthetic-refresh"}} {
		found, err := GetTokenByTokenValue(pair[1], pair[0])
		if err != nil || found == nil || found.GetId() != row.GetId() {
			t.Fatal("existing token lookup changed")
		}
	}
	for _, pair := range [][2]string{{"id_token", "unknown-id"}, {"", "synthetic-id"}, {"unknown", "synthetic-id"}} {
		found, err := GetTokenByTokenValue(pair[1], pair[0])
		if err != nil || found != nil {
			t.Fatal("unknown token or hint accepted")
		}
	}
	// Lookup retains the authoritative revocation state for the introspection caller.
	if ok, err := ExpireTokenByUser(row.Organization, row.User); err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	found, err := GetTokenByTokenValue("synthetic-id", "id_token")
	if err != nil || found == nil || found.ExpiresIn != 0 {
		t.Fatal("ID lookup lost revoked session state")
	}
	if ok, err := DeleteToken(row); err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	found, err = GetTokenByTokenValue("synthetic-id", "id_token")
	if err != nil || found != nil {
		t.Fatal("deleted session remains available")
	}
}
