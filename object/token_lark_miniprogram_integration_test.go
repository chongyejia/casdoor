package object

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xorm-io/xorm"
)

type syntheticLarkTransport func(*http.Request) (*http.Response, error)

func (f syntheticLarkTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func setupSyntheticLarkTokenFlow(t *testing.T) (*Application, *Organization, *User, *string) {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMaxOpenConns(1)
	if err := engine.Sync2(new(Application), new(Provider), new(Organization), new(User), new(Permission), new(Role), new(Cert), new(Token), new(ThirdPartyLink)); err != nil {
		t.Fatal(err)
	}
	previousOrmer := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: engine}
	previousTransport := http.DefaultTransport
	tenantKey := "tenant-A"
	http.DefaultTransport = syntheticLarkTransport(func(req *http.Request) (*http.Response, error) {
		var body string
		switch req.URL.Path {
		case "/open-apis/auth/v3/app_access_token/internal":
			body = `{"code":0,"app_access_token":"synthetic-app-token","expire":3600}`
		case "/open-apis/authen/v1/oidc/access_token":
			body = `{"code":0,"data":{"access_token":"synthetic-user-token"}}`
		case "/open-apis/authen/v1/user_info":
			body = `{"code":0,"data":{"user_id":"synthetic-user-id","open_id":"synthetic-open-id","union_id":"synthetic-union-id","tenant_key":"` + tenantKey + `"}}`
		default:
			t.Fatalf("unexpected external request: %s", req.URL.String())
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport; ormer = previousOrmer; engine.Close() })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	org := &Organization{Owner: "admin", Name: "synthetic-org"}
	provider := &Provider{Owner: "admin", Name: "synthetic-lark", Category: "OAuth", Type: "LarkMiniProgram", UserIdType: "user_id", ClientId: "synthetic-app-id", ClientSecret: "synthetic-app-secret"}
	app := &Application{Owner: "admin", Name: "synthetic-app", ClientId: "synthetic-client", Organization: org.Name, Cert: "synthetic-cert", ExpireInHours: 1, Providers: []*ProviderItem{{Name: provider.Name, CanSignIn: true, CanSignUp: true}}}
	user := &User{Owner: org.Name, Name: "synthetic-user", Id: "stable-synthetic-sub", Lark: "synthetic-user-id", Properties: map[string]string{"larkUserId": "synthetic-user-id", "larkAppId": "synthetic-app-id", "larkTenantKey": "tenant-A"}}
	cert := &Cert{Owner: org.Name, Name: app.Cert, PrivateKey: privateKey}
	for _, item := range []interface{}{org, provider, app, user, cert} {
		if _, err := engine.Insert(item); err != nil {
			t.Fatal(err)
		}
	}
	return app, org, user, &tenantKey
}

func requestSyntheticLarkToken(clientIp string) (interface{}, error) {
	return GetOAuthToken("", "synthetic-client", "", "synthetic-code", "", "", "", "", "", "lab.invalid", "", "lark_miniprogram", "", "en", "", "", "", "", "", "", "", "", clientIp)
}

func TestLarkMiniProgramFullTokenFlowRejectsDisabledApplication(t *testing.T) {
	app, _, _, _ := setupSyntheticLarkTokenFlow(t)
	app.DisableSignin = true
	if _, err := ormer.Engine.ID([]interface{}{app.Owner, app.Name}).Cols("disable_signin").Update(app); err != nil {
		t.Fatal(err)
	}
	result, err := requestSyntheticLarkToken("198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.(*TokenError); !ok {
		t.Fatalf("disabled application issued a token: %T", result)
	}
}

func requireSyntheticLarkDenied(t *testing.T, clientIp string) {
	t.Helper()
	beforeUsers, err := ormer.Engine.Count(new(User))
	if err != nil {
		t.Fatal(err)
	}
	beforeTokens, err := ormer.Engine.Count(new(Token))
	if err != nil {
		t.Fatal(err)
	}
	beforeUser := &User{Owner: "synthetic-org", Name: "synthetic-user"}
	beforeExists, err := ormer.Engine.Get(beforeUser)
	if err != nil {
		t.Fatal(err)
	}
	result, err := requestSyntheticLarkToken(clientIp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.(*TokenError); !ok {
		t.Fatalf("expected token rejection, got %T", result)
	}
	afterUsers, err := ormer.Engine.Count(new(User))
	if err != nil {
		t.Fatal(err)
	}
	afterTokens, err := ormer.Engine.Count(new(Token))
	if err != nil {
		t.Fatal(err)
	}
	afterUser := &User{Owner: "synthetic-org", Name: "synthetic-user"}
	afterExists, err := ormer.Engine.Get(afterUser)
	if err != nil {
		t.Fatal(err)
	}
	if beforeUsers != afterUsers || beforeTokens != afterTokens || beforeExists != afterExists || (beforeExists && !reflect.DeepEqual(beforeUser, afterUser)) {
		t.Fatal("rejected token flow mutated user or token records")
	}
}

func TestLarkMiniProgramFullTokenFlowAllowsScopedActiveUser(t *testing.T) {
	app, _, user, _ := setupSyntheticLarkTokenFlow(t)
	result, err := requestSyntheticLarkToken("198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.(*Token)
	if !ok {
		t.Fatalf("expected synthetic token, got %T: %+v", result, result)
	}
	cert, err := GetCert("synthetic-org/synthetic-cert")
	if err != nil || cert == nil {
		t.Fatalf("synthetic certificate missing: %v", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	_, issuer := getOriginFromHost("lab.invalid")
	for _, tc := range []struct{ name, value, tokenType string }{
		{"access", token.AccessToken, "access-token"},
		{"id", token.IdToken, "id-token"},
	} {
		claims := jwt.MapClaims{}
		parsed, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(app.ClientId), jwt.WithExpirationRequired()).ParseWithClaims(tc.value, claims, func(*jwt.Token) (interface{}, error) { return &privateKey.PublicKey, nil })
		if err != nil || !parsed.Valid {
			t.Fatalf("%s token failed signature/iss/aud/exp check: %v", tc.name, err)
		}
		if claims["sub"] != user.Id || claims["tokenType"] != tc.tokenType {
			t.Fatalf("%s token identity/type mismatch: %+v", tc.name, claims)
		}
	}
}

func TestLarkMiniProgramFullTokenFlowRejectsSigninPolicies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Application, *Organization, *User) error
	}{
		{"organization disabled", func(_ *Application, org *Organization, _ *User) error {
			org.DisableSignin = true
			_, err := ormer.Engine.ID([]interface{}{org.Owner, org.Name}).Cols("disable_signin").Update(org)
			return err
		}},
		{"IP restricted", func(app *Application, _ *Organization, _ *User) error {
			app.IpWhitelist = "203.0.113.0/24"
			_, err := ormer.Engine.ID([]interface{}{app.Owner, app.Name}).Cols("ip_whitelist").Update(app)
			return err
		}},
		{"tag mismatch", func(app *Application, _ *Organization, _ *User) error {
			app.Tags = []string{"approved"}
			_, err := ormer.Engine.ID([]interface{}{app.Owner, app.Name}).Cols("tags").Update(app)
			return err
		}},
		{"forbidden account", func(_ *Application, _ *Organization, user *User) error {
			user.IsForbidden = true
			_, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("is_forbidden").Update(user)
			return err
		}},
		{"soft deleted account", func(_ *Application, _ *Organization, user *User) error {
			user.IsDeleted = true
			_, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("is_deleted").Update(user)
			return err
		}},
		{"required MFA enrollment", func(_ *Application, org *Organization, _ *User) error {
			org.MfaItems = []*MfaItem{{Name: TotpType, Rule: "Required"}}
			_, err := ormer.Engine.ID([]interface{}{org.Owner, org.Name}).Cols("mfa_items").Update(org)
			return err
		}},
		{"MFA challenge", func(_ *Application, _ *Organization, user *User) error {
			user.PreferredMfaType = "totp"
			_, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("preferred_mfa_type").Update(user)
			return err
		}},
		{"password update challenge", func(_ *Application, _ *Organization, user *User) error {
			user.NeedUpdatePassword = true
			_, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("need_update_password").Update(user)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, org, user, _ := setupSyntheticLarkTokenFlow(t)
			if err := tc.change(app, org, user); err != nil {
				t.Fatal(err)
			}
			requireSyntheticLarkDenied(t, "198.51.100.7")
		})
	}
}

func TestLarkMiniProgramFullTokenFlowRejectsCrossTenantAndUnreviewedSignup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Application, *User, *string) error
	}{
		{"cross tenant", func(_ *Application, _ *User, tenant *string) error { *tenant = "tenant-B"; return nil }},
		{"cross app", func(app *Application, _ *User, _ *string) error {
			provider := &Provider{Owner: app.Owner, Name: "synthetic-lark", ClientId: "another-app-id"}
			_, err := ormer.Engine.ID([]interface{}{provider.Owner, provider.Name}).Cols("client_id").Update(provider)
			return err
		}},
		{"unscoped old row", func(_ *Application, user *User, _ *string) error {
			user.Properties = map[string]string{"larkUserId": "synthetic-user-id"}
			_, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("properties").Update(user)
			return err
		}},
		{"signup enabled but invitation required", func(app *Application, user *User, _ *string) error {
			app.EnableSignUp = true
			app.SignupItems = []*SignupItem{{Name: "invitationCode", Required: true}}
			if _, err := ormer.Engine.ID([]interface{}{app.Owner, app.Name}).Cols("enable_sign_up", "signup_items").Update(app); err != nil {
				return err
			}
			_, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Delete(user)
			return err
		}},
		{"duplicate binding", func(_ *Application, user *User, _ *string) error {
			duplicate := &User{Owner: user.Owner, Name: "synthetic-duplicate", Lark: user.Lark, Properties: user.Properties}
			_, err := ormer.Engine.Insert(duplicate)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _, user, tenant := setupSyntheticLarkTokenFlow(t)
			if err := tc.change(app, user, tenant); err != nil {
				t.Fatal(err)
			}
			requireSyntheticLarkDenied(t, "198.51.100.7")
			count, err := ormer.Engine.Count(new(Token))
			if err != nil || count != 0 {
				t.Fatalf("rejected flow persisted token: count=%d, err=%v", count, err)
			}
		})
	}
}

func TestLarkMiniProgramFullTokenFlowRejectsRequestedScope(t *testing.T) {
	for _, tc := range []struct{ name, scope, audience, resource string }{
		{"scope", "admin", "", ""}, {"audience", "", "other-client", ""}, {"resource", "", "", "other-resource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSyntheticLarkTokenFlow(t)
			result, err := GetOAuthToken("", "synthetic-client", "", "synthetic-code", "", tc.scope, "", "", "", "lab.invalid", "", "lark_miniprogram", "", "en", "", "", "", "", "", tc.audience, tc.resource, "", "198.51.100.7")
			if err != nil {
				t.Fatal(err)
			}
			if tokenErr, ok := result.(*TokenError); !ok || tokenErr.Error != InvalidScope {
				t.Fatalf("requested %s was not rejected: %T %+v", tc.name, result, result)
			}
		})
	}
}

func TestLarkMiniProgramFullTokenFlowRejectsExplicitPermissionDeny(t *testing.T) {
	app, org, user, _ := setupSyntheticLarkTokenFlow(t)
	permission := &Permission{
		Owner: org.Name, Name: "synthetic-deny", Users: []string{user.GetId()},
		ResourceType: "Application", Resources: []string{app.Name}, Actions: []string{"Read"},
		Effect: "Deny", State: "Approved", IsEnabled: true,
	}
	if ok, err := AddPermission(permission); err != nil || !ok {
		t.Fatalf("create synthetic deny permission: ok=%v, err=%v", ok, err)
	}
	allowed, err := CheckLoginPermission(user.GetId(), app)
	if err != nil || allowed {
		t.Fatalf("explicit deny permission not effective: allowed=%v, err=%v", allowed, err)
	}
	requireSyntheticLarkDenied(t, "198.51.100.7")
}
