package object

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func wechatResponseJSON(t *testing.T, result interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func requireWechatCompatibilityFields(t *testing.T, fields map[string]interface{}) {
	t.Helper()
	pairs := map[string]string{"access_token": "accessToken", "id_token": "idToken", "refresh_token": "refreshToken", "token_type": "tokenType", "expires_in": "expiresIn"}
	if len(fields) != 11 {
		t.Fatalf("expected exactly 11 public fields, got %d", len(fields))
	}
	for snake, camel := range pairs {
		a, ok := fields[snake]
		if !ok {
			t.Fatalf("missing %s", snake)
		}
		b, ok := fields[camel]
		if !ok || a != b {
			t.Fatalf("alias mismatch for %s", snake)
		}
	}
	if _, ok := fields["scope"].(string); !ok {
		t.Fatal("scope missing or not a string")
	}
	for _, name := range []string{"access_token", "id_token", "refresh_token", "token_type"} {
		if v, ok := fields[name].(string); !ok || v == "" {
			t.Fatalf("%s must be a nonempty string", name)
		}
	}
	if v, ok := fields["expires_in"].(float64); !ok || v <= 0 {
		t.Fatal("expires_in must be a positive number")
	}
}

func TestWechatTokenCompatMappingAndSwitch(t *testing.T) {
	token := &Token{AccessToken: "access", IdToken: "separate-id", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 3600, Scope: "openid", Code: "private-session-key", User: "private-user"}
	for _, setting := range []string{"", "true", "invalid"} {
		t.Run("enabled_"+setting, func(t *testing.T) {
			t.Setenv("wechatMiniProgramTokenCompat", setting)
			fields := wechatResponseJSON(t, wechatMiniProgramTokenResponse(token))
			requireWechatCompatibilityFields(t, fields)
			if fields["id_token"] != token.IdToken || fields["access_token"] != token.AccessToken || fields["refresh_token"] != token.RefreshToken || fields["token_type"] != token.TokenType || fields["expires_in"] != float64(token.ExpiresIn) || fields["scope"] != token.Scope {
				t.Fatal("mapping changed token values")
			}
		})
	}
	t.Setenv("wechatMiniProgramTokenCompat", "false")
	if wechatMiniProgramTokenResponse(token) != token {
		t.Fatal("explicit opt-out must restore upstream response")
	}
}

func setupSyntheticWechatTokenFlow(t *testing.T) (*Application, *User, *string) {
	t.Helper()
	app, _, user, _ := setupSyntheticLarkTokenFlow(t)
	provider := &Provider{Owner: "admin", Name: "synthetic-lark", Type: "WeChatMiniProgram"}
	if _, err := ormer.Engine.ID([]interface{}{provider.Owner, provider.Name}).Cols("type").Update(provider); err != nil {
		t.Fatal(err)
	}
	user.WeChat = "synthetic-wechat-openid"
	if _, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("wechat").Update(user); err != nil {
		t.Fatal(err)
	}
	body := `{"openid":"synthetic-wechat-openid","unionid":"synthetic-unionid","session_key":"private-session-key"}`
	http.DefaultTransport = syntheticLarkTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.weixin.qq.com" || req.URL.Path != "/sns/jscode2session" {
			t.Fatal("unexpected external request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	return app, user, &body
}

func requestSyntheticWechatToken() (interface{}, error) {
	return GetOAuthToken("", "synthetic-client", "", "synthetic-code", "", "", "", "", "", "lab.invalid", "", "wechat_miniprogram", "", "en", "", "", "", "", "", "", "", "", "198.51.100.7")
}

// This exercises the public entrypoint, not just the adapter: restoring the
// upstream `return token, nil` must fail even if the helper/tests survive sync.
func TestWechatTokenCompatFullFlow(t *testing.T) {
	t.Setenv("wechatMiniProgramTokenCompat", "")
	app, user, _ := setupSyntheticWechatTokenFlow(t)
	result, err := requestSyntheticWechatToken()
	if err != nil {
		t.Fatal(err)
	}
	fields := wechatResponseJSON(t, result)
	requireWechatCompatibilityFields(t, fields)
	cert, err := GetCert("synthetic-org/synthetic-cert")
	if err != nil || cert == nil {
		t.Fatal("missing synthetic cert")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	_, issuer := getOriginFromHost("lab.invalid")
	for field, kind := range map[string]string{"access_token": "access-token", "id_token": "id-token"} {
		claims := jwt.MapClaims{}
		parsed, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(app.ClientId), jwt.WithExpirationRequired()).ParseWithClaims(fields[field].(string), claims, func(*jwt.Token) (interface{}, error) { return &key.PublicKey, nil })
		if err != nil || !parsed.Valid {
			t.Fatalf("%s signature/claims invalid: %v", field, err)
		}
		if claims["sub"] != user.Id || claims["tokenType"] != kind {
			t.Fatalf("%s identity/type changed", field)
		}
	}
	stored := &Token{}
	if ok, err := ormer.Engine.Get(stored); err != nil || !ok {
		t.Fatal("token was not persisted")
	}
	if stored.Code != "private-session-key" || stored.IdToken != fields["id_token"] || stored.AccessToken != fields["access_token"] {
		t.Fatal("response differs from persisted token")
	}
}

func TestWechatTokenCompatErrorsUnchanged(t *testing.T) {
	for _, setting := range []string{"true", "false"} {
		for _, scenario := range []string{"invalid-code", "empty-session", "missing-provider", "forbidden", "deleted", "storage-error"} {
			t.Run(setting+"/"+scenario, func(t *testing.T) {
				t.Setenv("wechatMiniProgramTokenCompat", setting)
				app, user, body := setupSyntheticWechatTokenFlow(t)
				expected := InvalidGrant
				var err error
				switch scenario {
				case "invalid-code":
					*body = `{"errcode":40029,"errmsg":"invalid code"}`
				case "empty-session":
					*body = `{}`
					expected = InvalidRequest
				case "missing-provider":
					app.Providers = nil
					_, err = ormer.Engine.ID([]interface{}{app.Owner, app.Name}).Cols("providers").Update(app)
					expected = InvalidClient
				case "forbidden":
					user.IsForbidden = true
					_, err = ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("is_forbidden").Update(user)
				case "deleted":
					user.IsDeleted = true
					_, err = ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("is_deleted").Update(user)
				case "storage-error":
					err = ormer.Engine.DropTables(new(Token))
				}
				if err != nil {
					t.Fatal(err)
				}
				result, err := requestSyntheticWechatToken()
				if scenario == "storage-error" {
					if err == nil || result != nil {
						t.Fatal("storage failure must propagate error without response")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				tokenErr, ok := result.(*TokenError)
				if !ok || tokenErr.Error != expected {
					t.Fatalf("unexpected error response type/code: %T", result)
				}
				fields := wechatResponseJSON(t, result)
				if len(fields) != 2 || fields["error"] != expected {
					t.Fatal("error contract changed")
				}
				if count, err := ormer.Engine.Count(new(Token)); err != nil || count != 0 {
					t.Fatal("rejected flow persisted token")
				}
			})
		}
	}
}
