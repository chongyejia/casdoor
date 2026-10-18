package object

import (
	"testing"

	"github.com/casdoor/casdoor/cred"
)

func TestPasswordlessMasterGrantApplicationIsExactAndOptIn(t *testing.T) {
	app := &Application{Owner: "admin", Name: "synthetic-app", Organization: "synthetic-org"}
	user := &User{Owner: "synthetic-org"}
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "")
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", "")
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_PAIRS", "")
	if isPasswordlessMasterGrantApplication(app, user) {
		t.Fatal("passwordless master grant must be disabled by default")
	}

	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "admin/synthetic-app")
	if isPasswordlessMasterGrantApplication(app, user) {
		t.Fatal("organization opt-in is required separately")
	}
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", "synthetic-org")
	if !isPasswordlessMasterGrantApplication(app, user) {
		t.Fatal("exact application should be opted in")
	}
	if isPasswordlessMasterGrantApplication(&Application{Owner: "other", Name: "synthetic-app", Organization: "synthetic-org"}, user) {
		t.Fatal("same app name under another owner must be rejected")
	}
	if isPasswordlessMasterGrantApplication(&Application{Owner: "admin", Name: "other-app", Organization: "synthetic-org"}, user) {
		t.Fatal("another application must be rejected")
	}
	if isPasswordlessMasterGrantApplication(&Application{Owner: "admin", Name: "synthetic-app", Organization: "other-org"}, user) {
		t.Fatal("application in another organization must be rejected")
	}
	if isPasswordlessMasterGrantApplication(app, &User{Owner: "other-org"}) {
		t.Fatal("user in another organization must be rejected")
	}
	app.IsShared = true
	if isPasswordlessMasterGrantApplication(app, user) {
		t.Fatal("shared application must be rejected")
	}
}

func TestPasswordlessMasterGrantPairsAreExactAndBackwardCompatible(t *testing.T) {
	builtin := &Application{Owner: "admin", Name: "app-built-in", Organization: "built-in"}
	builtinUser := &User{Owner: "built-in"}
	oms := &Application{Owner: "admin", Name: "oms", Organization: "cyj-inner"}
	omsUser := &User{Owner: "cyj-inner"}
	other := &Application{Owner: "admin", Name: "other-app", Organization: "cyj-inner"}

	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "admin/app-built-in")
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", "built-in")
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_PAIRS", "")
	if !isPasswordlessMasterGrantApplication(builtin, builtinUser) || isPasswordlessMasterGrantApplication(oms, omsUser) {
		t.Fatal("legacy single pair must keep its exact behaviour")
	}

	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_PAIRS", " admin/oms@cyj-inner , ")
	if !isPasswordlessMasterGrantApplication(builtin, builtinUser) {
		t.Fatal("legacy pair must stay allowed when pairs are added")
	}
	if !isPasswordlessMasterGrantApplication(oms, omsUser) {
		t.Fatal("listed pair must be allowed")
	}
	if isPasswordlessMasterGrantApplication(other, omsUser) {
		t.Fatal("unlisted application in a listed organization must be rejected")
	}
	if isPasswordlessMasterGrantApplication(oms, builtinUser) {
		t.Fatal("user outside the listed organization must be rejected")
	}
	if isPasswordlessMasterGrantApplication(&Application{Owner: "admin", Name: "oms", Organization: "built-in"}, builtinUser) {
		t.Fatal("listed application moved to another organization must be rejected")
	}
	shared := *oms
	shared.IsShared = true
	if isPasswordlessMasterGrantApplication(&shared, omsUser) {
		t.Fatal("shared application must be rejected")
	}

	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "")
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_ORGANIZATION", "")
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_PAIRS", "admin/app-built-in@built-in,admin/oms@cyj-inner")
	if !isPasswordlessMasterGrantApplication(builtin, builtinUser) || !isPasswordlessMasterGrantApplication(oms, omsUser) {
		t.Fatal("pairs variable alone must allow both listed pairs")
	}

	for _, malformed := range []string{
		"admin/oms", "oms@cyj-inner", "admin/@cyj-inner", "/oms@cyj-inner", "admin/oms@",
		"admin/oms@cyj-inner@x", "admin/oms/x@cyj-inner", "admin/oms@cyj/inner", "admin/oms @cyj-inner", "*@*",
	} {
		t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_PAIRS", malformed)
		if isPasswordlessMasterGrantApplication(oms, omsUser) {
			t.Fatalf("malformed pair %q must not allow anything", malformed)
		}
	}
}

func TestPasswordlessMasterGrantRequiresAuthenticatedClient(t *testing.T) {
	app := &Application{ClientSecret: "synthetic-client-secret"}
	if !isPasswordlessMasterGrantClientAuthenticated(app, "synthetic-client-secret") {
		t.Fatal("matching synthetic client secret must authenticate")
	}
	for _, submitted := range []string{"", "synthetic-wrong-client-secret"} {
		if isPasswordlessMasterGrantClientAuthenticated(app, submitted) {
			t.Fatal("missing or incorrect client secret must be rejected")
		}
	}
	if isPasswordlessMasterGrantClientAuthenticated(&Application{}, "synthetic-client-secret") {
		t.Fatal("application without a registered client secret must be rejected")
	}
}

func TestPasswordlessMasterGrantRequiresMasterPassword(t *testing.T) {
	manager := cred.GetCredManager("plain")
	organization := &Organization{MasterPassword: "synthetic-master", PasswordType: "plain"}
	if !isOrganizationMasterPasswordCorrect("synthetic-master", organization, manager) {
		t.Fatal("matching synthetic organization master password should pass")
	}
	for _, password := range []string{"", "incorrect-password"} {
		if isOrganizationMasterPasswordCorrect(password, organization, manager) {
			t.Fatal("empty or incorrect password must be rejected")
		}
	}
	if isOrganizationMasterPasswordCorrect("synthetic-master", &Organization{PasswordType: "plain"}, manager) {
		t.Fatal("organization without a master password must be rejected")
	}
	saltedManager := cred.GetCredManager("salt")
	saltedOrganization := &Organization{
		MasterPassword: saltedManager.GetHashedPassword("synthetic-master", "synthetic-salt"),
		PasswordSalt:   "synthetic-salt",
		PasswordType:   "salt",
	}
	if !isOrganizationMasterPasswordCorrect("synthetic-master", saltedOrganization, saltedManager) {
		t.Fatal("matching synthetic salted master password should pass")
	}
	if isOrganizationMasterPasswordCorrect("incorrect-password", saltedOrganization, saltedManager) {
		t.Fatal("incorrect password must not match a salted master password")
	}
}

func TestPasswordlessMasterGrantDoesNotChangeMfaRejection(t *testing.T) {
	user := &User{PreferredMfaType: "totp"}
	if getMfaUserTokenError(user) == nil {
		t.Fatal("MFA-enabled user must still be rejected by password grant")
	}
	for _, blocked := range []*User{{IsForbidden: true}, {IsDeleted: true}} {
		if CheckApplicationSignin(&Application{}, blocked, "", "en") == nil {
			t.Fatal("forbidden or deleted user must still be rejected")
		}
	}
}
