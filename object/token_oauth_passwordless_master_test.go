package object

import (
	"testing"

	"github.com/casdoor/casdoor/cred"
)

func TestPasswordlessMasterGrantApplicationIsExactAndOptIn(t *testing.T) {
	app := &Application{Owner: "admin", Name: "synthetic-app"}
	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "")
	if isPasswordlessMasterGrantApplication(app) {
		t.Fatal("passwordless master grant must be disabled by default")
	}

	t.Setenv("CASDOOR_PASSWORDLESS_MASTER_GRANT_APPLICATION", "admin/synthetic-app")
	if !isPasswordlessMasterGrantApplication(app) {
		t.Fatal("exact application should be opted in")
	}
	if isPasswordlessMasterGrantApplication(&Application{Owner: "other", Name: "synthetic-app"}) {
		t.Fatal("same app name under another owner must be rejected")
	}
	if isPasswordlessMasterGrantApplication(&Application{Owner: "admin", Name: "other-app"}) {
		t.Fatal("another application must be rejected")
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
