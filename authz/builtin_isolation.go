package authz

import "strings"

// A built-in business identity cannot obtain management access through the
// wildcard API model, is_admin, or a business role. Self operations still pass
// their controller's password/MFA/field-level checks.
func builtinUserAPIAllowed(name, method, path, owner, objectName string) bool {
	if method == "GET" {
		// Discovery retains the actual application name in the request path.
		if strings.HasPrefix(path, "/.well-known/") {
			return true
		}
		switch path {
		case "/api/userinfo", "/api/user", "/api/get-account", "/api/get-application", "/api/get-default-application", "/api/health", "/api/logout", "/api/sso-logout", "/api/login/oauth":
			return true
		// Public pre-authentication endpoints must also work with a built-in cookie.
		case "/api/get-app-login", "/api/get-captcha", "/api/get-captcha-status", "/api/get-email-and-phone", "/api/get-organization-names", "/api/get-saml-login", "/api/get-invitation-info", "/api/get-qrcode", "/api/get-webhook-event", "/api/faceid-signin-begin", "/api/kerberos-login":
			return true
		case "/api/get-provider": // Telegram login reads public provider settings; masking/admin checks remain in the controller.
			return true
		case "/api/saml/metadata": // Public SAML discovery metadata, already available anonymously.
			return true
		case "/api/webauthn/signin/begin": // The public passkey login challenge is a GET route.
			return true
		case "/api/get-user", "/api/get-session", "/api/is-session-duplicated":
			return owner == "built-in" && objectName == name
		}
	}
	if method == "POST" {
		switch path {
		case "/api/login", "/api/logout", "/api/sso-logout", "/api/login/oauth", "/api/callback", "/api/set-password", "/api/send-verification-code", "/api/verify-code", "/api/verify-captcha", "/api/reset-email-or-phone", "/api/unlink":
			return true
		case "/api/webauthn/signin/finish":
			return true
		case "/api/check-user-password", "/api/mfa/setup/initiate", "/api/mfa/setup/verify", "/api/mfa/setup/enable", "/api/delete-mfa", "/api/set-preferred-mfa", "/api/delete-session":
			return owner == "built-in" && objectName == name
		}
	}
	return false
}
