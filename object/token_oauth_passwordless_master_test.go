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
