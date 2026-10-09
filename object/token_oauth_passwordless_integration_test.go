package object

import (
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xorm-io/core"
)

const (
	syntheticPasswordlessApplication = "admin/synthetic-app"
	syntheticPasswordlessOrg         = "synthetic-org"
	syntheticPasswordlessClientID    = "synthetic-client"
	syntheticPasswordlessSecret      = "synthetic-client-secret"
	syntheticPasswordlessMaster      = "synthetic-master-password"
	syntheticPasswordlessUser        = "synthetic-user"
)

func setupSyntheticPasswordlessPasswordGrant(t *testing.T) (*Application, *Organization, *User) {
	t.Helper()
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "")
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", "")

	app, org, user, _ := setupSyntheticLarkTokenFlow(t)
	if err := ormer.Engine.Sync2(new(Syncer)); err != nil {
		t.Fatal(err)
	}
	app.ClientSecret = syntheticPasswordlessSecret
	app.GrantTypes = []string{"password"}
	if _, err := ormer.Engine.ID(core.PK{app.Owner, app.Name}).Cols("client_secret", "grant_types").Update(app); err != nil {
		t.Fatal(err)
	}
	org.PasswordType = "plain"
	org.MasterPassword = syntheticPasswordlessMaster
	if _, err := ormer.Engine.ID(core.PK{org.Owner, org.Name}).Cols("password_type", "master_password").Update(org); err != nil {
		t.Fatal(err)
	}
	return app, org, user
}

func requestSyntheticPasswordlessPasswordGrant(username, password, clientSecret string) (interface{}, error) {
	return GetOAuthToken("password", syntheticPasswordlessClientID, clientSecret, "", "", "", "", username, password, "lab.invalid", "", "", "", "en", "", "", "", "", "", "", "", "", "198.51.100.8")
}

func enableSyntheticPasswordlessMasterGrant(t *testing.T) {
	t.Helper()
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", syntheticPasswordlessApplication)
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", syntheticPasswordlessOrg)
}

func syntheticPasswordGrantUserSnapshot(t *testing.T) map[string]User {
	t.Helper()
	users := []*User{}
	if err := ormer.Engine.Find(&users); err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string]User, len(users))
	for _, user := range users {
		snapshot[user.GetId()] = *user
	}
	return snapshot
}

func requireSyntheticPasswordGrantDeniedWithoutMutation(t *testing.T, username, password, clientSecret, expectedSigninFailureUser string) {
	t.Helper()
	beforeUsers := syntheticPasswordGrantUserSnapshot(t)
	beforeTokens, err := ormer.Engine.Count(new(Token))
	if err != nil {
		t.Fatal(err)
	}

	attemptStarted := time.Now().UTC()
	result, err := requestSyntheticPasswordlessPasswordGrant(username, password, clientSecret)
	if err != nil {
		t.Fatalf("password grant returned an unexpected error: %v", err)
	}
	tokenError, ok := result.(*TokenError)
	if !ok {
		t.Fatalf("expected password grant rejection, got %T", result)
	}

	afterUsers := syntheticPasswordGrantUserSnapshot(t)
	afterTokens, err := ormer.Engine.Count(new(Token))
	if err != nil {
		t.Fatal(err)
	}
	if beforeTokens != afterTokens {
		t.Fatalf("rejected password grant added token records: before=%d after=%d", beforeTokens, afterTokens)
	}
	if expectedSigninFailureUser == "" {
		if !reflect.DeepEqual(beforeUsers, afterUsers) {
			t.Fatal("rejected password grant changed user records")
		}
		return
	}

	if len(beforeUsers) != len(afterUsers) {
		t.Fatal("rejected password grant changed the set of user records")
	}
	for id, before := range beforeUsers {
		after, ok := afterUsers[id]
		if !ok {
			t.Fatal("rejected password grant removed a user record")
		}
		if id == expectedSigninFailureUser {
			wantSigninWrongTimes := before.SigninWrongTimes
			if wantSigninWrongTimes < DefaultFailedSigninLimit {
				wantSigninWrongTimes++
			}
			if after.SigninWrongTimes != wantSigninWrongTimes {
				t.Fatalf("failed signin count=%d, want %d (rejection=%s: %s)", after.SigninWrongTimes, wantSigninWrongTimes, tokenError.Error, tokenError.ErrorDescription)
			}
			if wantSigninWrongTimes >= DefaultFailedSigninLimit {
				failedAt, parseErr := time.Parse(time.RFC3339, after.LastSigninWrongTime)
				if parseErr != nil || failedAt.Before(attemptStarted.Add(-time.Second)) || failedAt.After(time.Now().UTC().Add(time.Second)) {
					t.Fatal("failed signin timestamp does not match lockout policy")
				}
			} else if after.LastSigninWrongTime != before.LastSigninWrongTime {
				t.Fatal("failed signin timestamp changed before the lockout threshold")
			}
			before.SigninWrongTimes = after.SigninWrongTimes
			before.LastSigninWrongTime = after.LastSigninWrongTime
			updatedAt, parseErr := time.Parse(time.RFC3339, after.UpdatedTime)
			if parseErr != nil || updatedAt.Before(attemptStarted.Add(-time.Second)) || updatedAt.After(time.Now().UTC().Add(time.Second)) {
				t.Fatal("user updated time does not match the failed signin write")
			}
			before.UpdatedTime = after.UpdatedTime
			if err := before.UpdateUserHash(); err != nil {
				t.Fatalf("recompute expected user hash: %v", err)
			}
		}
		if !reflect.DeepEqual(before, after) {
			changedFields := []string{}
			beforeValue := reflect.ValueOf(before)
			afterValue := reflect.ValueOf(after)
			for i := 0; i < beforeValue.NumField(); i++ {
				if !reflect.DeepEqual(beforeValue.Field(i).Interface(), afterValue.Field(i).Interface()) {
					changedFields = append(changedFields, reflect.TypeOf(before).Field(i).Name)
				}
			}
			t.Fatalf("rejected password grant changed user fields outside the signin failure policy for %s: %v", id, changedFields)
		}
	}
}

func TestPasswordlessMasterPasswordGrantMintsVerifiedTokens(t *testing.T) {
	app, _, user := setupSyntheticPasswordlessPasswordGrant(t)
	enableSyntheticPasswordlessMasterGrant(t)
	result, err := requestSyntheticPasswordlessPasswordGrant(user.Name, syntheticPasswordlessMaster, syntheticPasswordlessSecret)
	if err != nil {
		t.Fatal(err)
	}
	tokens, ok := result.(*TokenWrapper)
	if !ok {
		t.Fatalf("expected password grant token wrapper, got %T", result)
	}
	if tokens.AccessToken == "" || tokens.IdToken == "" {
		t.Fatal("successful password grant must issue access and ID tokens")
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
		{"access", tokens.AccessToken, "access-token"},
		{"id", tokens.IdToken, "id-token"},
	} {
		claims := jwt.MapClaims{}
		parsed, err := jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithIssuer(issuer),
			jwt.WithAudience(app.ClientId),
			jwt.WithExpirationRequired(),
		).ParseWithClaims(tc.value, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != "RS256" {
				t.Fatalf("%s token algorithm is %q, want RS256", tc.name, token.Method.Alg())
			}
			return &privateKey.PublicKey, nil
		})
		if err != nil || parsed == nil || !parsed.Valid {
			t.Fatalf("%s token failed signature/iss/aud/exp validation: %v", tc.name, err)
		}
		if claims["sub"] != user.Id || claims["tokenType"] != tc.tokenType {
			t.Fatalf("%s token identity/type mismatch", tc.name)
		}
	}
}

func TestPasswordlessMasterPasswordGrantRequiresBothOptInFlags(t *testing.T) {
	for _, tc := range []struct {
		name       string
		appSetting string
		orgSetting string
	}{
		{name: "disabled by default"},
		{name: "application only", appSetting: syntheticPasswordlessApplication},
		{name: "organization only", orgSetting: syntheticPasswordlessOrg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, user := setupSyntheticPasswordlessPasswordGrant(t)
			t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", tc.appSetting)
			t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", tc.orgSetting)
			requireSyntheticPasswordGrantDeniedWithoutMutation(t, user.Name, syntheticPasswordlessMaster, syntheticPasswordlessSecret, "")
		})
	}
}

func TestPasswordlessMasterPasswordGrantRejectsInvalidCredentialsAndUsers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		setup         func(*testing.T, *Application, *Organization, *User)
		secret        string
		pass          string
		signinFailure bool
	}{
		{name: "missing client secret", secret: "", pass: syntheticPasswordlessMaster},
		{name: "incorrect client secret", secret: "synthetic-wrong-secret", pass: syntheticPasswordlessMaster},
		{name: "incorrect organization master password", secret: syntheticPasswordlessSecret, pass: "synthetic-wrong-master", signinFailure: true},
		{name: "MFA enabled", secret: syntheticPasswordlessSecret, pass: syntheticPasswordlessMaster, setup: func(t *testing.T, _ *Application, _ *Organization, user *User) {
			user.PreferredMfaType = "totp"
			if _, err := ormer.Engine.ID(core.PK{user.Owner, user.Name}).Cols("preferred_mfa_type").Update(user); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "forbidden user", secret: syntheticPasswordlessSecret, pass: syntheticPasswordlessMaster, setup: func(t *testing.T, _ *Application, _ *Organization, user *User) {
			user.IsForbidden = true
			if _, err := ormer.Engine.ID(core.PK{user.Owner, user.Name}).Cols("is_forbidden").Update(user); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "soft deleted user", secret: syntheticPasswordlessSecret, pass: syntheticPasswordlessMaster, setup: func(t *testing.T, _ *Application, _ *Organization, user *User) {
			user.IsDeleted = true
			if _, err := ormer.Engine.ID(core.PK{user.Owner, user.Name}).Cols("is_deleted").Update(user); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "non-empty user rejects incorrect password", secret: syntheticPasswordlessSecret, pass: "synthetic-wrong-user-password", signinFailure: true, setup: func(t *testing.T, _ *Application, _ *Organization, user *User) {
			user.Password = "synthetic-stored-password"
			user.PasswordType = "plain"
			if _, err := ormer.Engine.ID(core.PK{user.Owner, user.Name}).Cols("password", "password_type").Update(user); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "shared application", secret: syntheticPasswordlessSecret, pass: syntheticPasswordlessMaster, setup: func(t *testing.T, _ *Application, _ *Organization, _ *User) {
			app, err := GetApplicationByClientId(syntheticPasswordlessClientID)
			if err != nil {
				t.Fatal(err)
			}
			app.IsShared = true
			if _, err := ormer.Engine.ID(core.PK{app.Owner, app.Name}).Cols("is_shared").Update(app); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "shared application cannot use a cross-organization user", secret: syntheticPasswordlessSecret, pass: syntheticPasswordlessMaster, setup: func(t *testing.T, app *Application, _ *Organization, user *User) {
			app.IsShared = true
			if _, err := ormer.Engine.ID(core.PK{app.Owner, app.Name}).Cols("is_shared").Update(app); err != nil {
				t.Fatal(err)
			}
			foreignOrg := &Organization{Owner: "admin", Name: "synthetic-foreign-org", DefaultApplication: app.Name}
			if _, err := ormer.Engine.Insert(foreignOrg); err != nil {
				t.Fatal(err)
			}
			foreignUser := &User{Owner: foreignOrg.Name, Name: user.Name, Id: "stable-foreign-sub"}
			if _, err := ormer.Engine.Insert(foreignUser); err != nil {
				t.Fatal(err)
			}
			if _, err := ormer.Engine.ID(core.PK{user.Owner, user.Name}).Delete(new(User)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, org, user := setupSyntheticPasswordlessPasswordGrant(t)
			enableSyntheticPasswordlessMasterGrant(t)
			if tc.setup != nil {
				app := &Application{Owner: "admin", Name: "synthetic-app", Organization: org.Name}
				if _, err := ormer.Engine.Get(app); err != nil {
					t.Fatal(err)
				}
				tc.setup(t, app, org, user)
			}
			expectedSigninFailureUser := ""
			if tc.signinFailure {
				expectedSigninFailureUser = user.GetId()
			}
			requireSyntheticPasswordGrantDeniedWithoutMutation(t, user.Name, tc.pass, tc.secret, expectedSigninFailureUser)
		})
	}
}
