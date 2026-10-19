package object

import "github.com/casdoor/casdoor/conf"

// Local patch: only the successful WeChat Mini Program response uses this
// adapter. See docs/LOCAL-PATCHES.md before syncing upstream or removing it.
func wechatMiniProgramTokenResponse(token *Token) interface{} {
	if conf.GetConfigString("wechatMiniProgramTokenCompat") == "false" {
		return token // Explicit opt-out restores the upstream response.
	}

	// Never embed Token: it contains the WeChat session key and internal state.
	return &struct {
		*TokenWrapper
		AccessToken  string `json:"accessToken"`
		IdToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken"`
		TokenType    string `json:"tokenType"`
		ExpiresIn    int    `json:"expiresIn"`
	}{
		TokenWrapper: &TokenWrapper{
			AccessToken: token.AccessToken, IdToken: token.IdToken,
			RefreshToken: token.RefreshToken, TokenType: token.TokenType,
			ExpiresIn: token.ExpiresIn, Scope: token.Scope,
		},
		AccessToken: token.AccessToken, IdToken: token.IdToken,
		RefreshToken: token.RefreshToken, TokenType: token.TokenType,
		ExpiresIn: token.ExpiresIn,
	}
}
