package object

import (
	"net/http"
	"time"

	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/util"
)

// GetLarkMiniProgramToken exchanges a Lark mini-program authorization code
// through the application's configured provider. It never searches across
// Lark ID types or organizations when choosing an existing Casdoor account.
func GetLarkMiniProgramToken(application *Application, code, host, _username, _avatar, lang, clientIp string) (*Token, *TokenError, error) {
	mpProvider := GetLarkMiniProgramProvider(application)
	if mpProvider == nil || mpProvider.Owner == "" {
		return nil, &TokenError{Error: InvalidClient, ErrorDescription: "the application does not support lark mini program"}, nil
	}
	if code == "" {
		return nil, &TokenError{Error: InvalidRequest, ErrorDescription: "lark mini program code is missing"}, nil
	}
	if larkPropertyKey(mpProvider.UserIdType) == "" {
		return nil, &TokenError{Error: InvalidRequest, ErrorDescription: "lark mini program requires an explicit userIdType"}, nil
	}
	providerItem := application.GetProviderItem(mpProvider.Name)
	if providerItem == nil || !providerItem.CanSignIn {
		return nil, &TokenError{Error: InvalidClient, ErrorDescription: "lark mini program sign-in is disabled"}, nil
	}
	provider, err := GetProvider(util.GetId(mpProvider.Owner, mpProvider.Name))
	if err != nil {
		return nil, nil, err
	}
	if provider == nil || provider.Type != "LarkMiniProgram" || provider.UserIdType != mpProvider.UserIdType {
		return nil, &TokenError{Error: InvalidClient, ErrorDescription: "lark mini program provider changed"}, nil
	}
	lark := idp.NewLarkIdProvider(provider.ClientId, provider.ClientSecret, "", false, provider.UserIdType)
	lark.SetHttpClient(&http.Client{Timeout: 10 * time.Second})
	appToken, err := lark.GetToken(code)
	if err != nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "lark app token exchange failed"}, nil
	}
	info, err := lark.GetUserInfo(appToken)
	if err != nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "lark user code exchange failed"}, nil
	}
	return getLarkMiniProgramTokenForIdentity(application, providerItem, provider.UserIdType, info, host, clientIp, lang)
}

func getLarkMiniProgramTokenForIdentity(application *Application, providerItem *ProviderItem, idType string, info *idp.UserInfo, host, clientIp, lang string) (*Token, *TokenError, error) {
	if application == nil || application.Organization == "" || info == nil || info.Id == "" ||
		providerItem == nil || !providerItem.CanSignIn || larkPropertyKey(idType) == "" || info.Extra[larkPropertyKey(idType)] != info.Id ||
		info.Extra["larkTenantKey"] == "" || info.Extra["larkAppId"] == "" {
		return nil, &TokenError{Error: InvalidRequest, ErrorDescription: "the lark mini program identity is invalid"}, nil
	}
	user, err := GetUserByLarkIdentity(application.Organization, idType, info.Id, info.Extra["larkAppId"], info.Extra["larkTenantKey"])
	if err != nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "the lark identity needs manual review"}, nil
	}
	if user == nil {
		// This direct token endpoint has no invitation or MFA enrollment
		// challenge. New accounts must use a reviewed signup flow instead.
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "lark mini program signup requires a reviewed flow"}, nil
	}
	if user.NeedUpdatePassword || user.IsMfaEnabled() || application.OrganizationObj == nil || IsNeedPromptMfa(application.OrganizationObj, user) {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "the lark account requires an interactive sign-in challenge"}, nil
	}
	if tokenError := checkGrantUserSignin(application, user, clientIp, lang); tokenError != nil {
		return nil, tokenError, nil
	}
	token, err := GetTokenByUser(application, user, "", "", "", host)
	if err != nil {
		return nil, nil, err
	}
	return token, nil, nil
}
