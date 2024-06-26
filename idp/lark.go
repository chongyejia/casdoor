// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type LarkIdProvider struct {
	Client     *http.Client
	Config     *oauth2.Config
	UserIdType string
}

func NewLarkIdProvider(clientId, clientSecret, redirectUrl, userIdType string) *LarkIdProvider {
	return &LarkIdProvider{
		Config: &oauth2.Config{
			Scopes:       []string{},
			Endpoint:     oauth2.Endpoint{TokenURL: "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"},
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  redirectUrl,
		},
		UserIdType: userIdType,
	}
}

func (idp *LarkIdProvider) SetHttpClient(client *http.Client) {
	idp.Client = client
}

/*
{
    "app_access_token": "t-g1044ghJRUIJJ5ZPPZMOHKWZISL33E4QSS3abcef",
    "code": 0,
    "expire": 7200,
    "msg": "ok",
    "tenant_access_token": "t-g1044ghJRUIJJ5ZPPZMOHKWZISL33E4QSS3abcef"
}
*/

type LarkAccessToken struct {
	Code              int    `json:"code"`
	Expire            int    `json:"expire"`
	Msg               string `json:"msg"`
	TenantAccessToken string `json:"tenant_access_token"`
	AppAccessToken    string `json:"app_access_token"`
}

// GetToken uses code to get access_token
func (idp *LarkIdProvider) GetToken(code string) (*oauth2.Token, error) {
	params := map[string]string{
		"app_id":     idp.Config.ClientID,
		"app_secret": idp.Config.ClientSecret,
	}

	data, err := idp.postWithBody(params, idp.Config.Endpoint.TokenURL)
	if err != nil {
		return nil, err
	}

	var appToken LarkAccessToken
	if err = json.Unmarshal(data, &appToken); err != nil {
		return nil, err
	}

	if appToken.Code != 0 {
		return nil, fmt.Errorf("GetToken() error, appToken.Code: %d, appToken.Msg: %s", appToken.Code, appToken.Msg)
	}

	token := &oauth2.Token{
		AccessToken: appToken.AppAccessToken,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Second * time.Duration(appToken.Expire)),
	}

	return token.WithExtra(map[string]interface{}{"code": code}), nil
}

/*
{
    "code": 0,
    "msg": "success",
    "data": {
        "access_token": "u-5Dak9ZAxJ9tFUn8MaTD_BFM51FNdg5xzO0y010000HWb",
        "refresh_token": "ur-6EyFQZyplb9URrOx5NtT_HM53zrJg59HXwy040400G.e",
        "token_type": "Bearer",
        "expires_in": 7199,
        "refresh_expires_in": 2591999,
        "scope": "auth:user.id:read bitable:app"
    }
}
*/

type LarkUserAccessToken struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int    `json:"expires_in"`
		RefreshExpiresIn int    `json:"refresh_expires_in"`
		Scope            string `json:"scope"`
	} `json:"data"`
}

/*
{
    "code": 0,
    "msg": "success",
    "data": {
        "name": "zhangsan",
        "en_name": "zhangsan",
        "avatar_url": "www.feishu.cn/avatar/icon",
        "avatar_thumb": "www.feishu.cn/avatar/icon_thumb",
        "avatar_middle": "www.feishu.cn/avatar/icon_middle",
        "avatar_big": "www.feishu.cn/avatar/icon_big",
        "open_id": "ou-caecc734c2e3328a62489fe0648c4b98779515d3",
        "union_id": "on-d89jhsdhjsajkda7828enjdj328ydhhw3u43yjhdj",
        "email": "zhangsan@feishu.cn",
        "enterprise_email": "demo@mail.com",
        "user_id": "5d9bdxxx",
        "mobile": "+86130002883xx",
        "tenant_key": "736588c92lxf175d",
		"employee_no": "111222333"
    }
}
*/

type LarkUserInfo struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Name            string `json:"name"`
		EnName          string `json:"en_name"`
		AvatarUrl       string `json:"avatar_url"`
		AvatarThumb     string `json:"avatar_thumb"`
		AvatarMiddle    string `json:"avatar_middle"`
		AvatarBig       string `json:"avatar_big"`
		OpenId          string `json:"open_id"`
		UnionId         string `json:"union_id"`
		Email           string `json:"email"`
		EnterpriseEmail string `json:"enterprise_email"`
		UserId          string `json:"user_id"`
		Mobile          string `json:"mobile"`
		TenantKey       string `json:"tenant_key"`
		EmployeeNo      string `json:"employee_no"`
	} `json:"data"`
}

// GetUserInfo uses LarkAccessToken to return LinkedInUserInfo
func (idp *LarkIdProvider) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {
	userAccessToken, err := idp.requestUserAccessToken(token)
	if err != nil {
		return nil, err
	}

	return idp.requestUserInfo(userAccessToken)
}

func (idp *LarkIdProvider) requestUserAccessToken(token *oauth2.Token) (*LarkUserAccessToken, error) {
	body := map[string]string{
		"grant_type": "authorization_code",
		"code":       token.Extra("code").(string),
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := idp.createRequest("POST", "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token", data, token.AccessToken)
	if err != nil {
		return nil, err
	}

	resp, err := idp.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return idp.parseUserAccessToken(resp.Body)
}

func (idp *LarkIdProvider) requestUserInfo(userAccessToken *LarkUserAccessToken) (*UserInfo, error) {
	req, err := idp.createRequest("GET", "https://open.feishu.cn/open-apis/authen/v1/user_info", nil, userAccessToken.Data.AccessToken)
	if err != nil {
		return nil, err
	}

	resp, err := idp.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return idp.parseUserInfo(resp.Body)
}

func (idp *LarkIdProvider) createRequest(method, url string, body []byte, accessToken string) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return req, nil
}

func (idp *LarkIdProvider) parseUserAccessToken(body io.Reader) (*LarkUserAccessToken, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var userAccessToken LarkUserAccessToken
	if err = json.Unmarshal(data, &userAccessToken); err != nil {
		return nil, err
	}

	return &userAccessToken, nil
}

func (idp *LarkIdProvider) parseUserInfo(body io.Reader) (*UserInfo, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var larkUserInfo LarkUserInfo
	if err = json.Unmarshal(data, &larkUserInfo); err != nil {
		return nil, err
	}

	userId := idp.getUserId(larkUserInfo)
	email := idp.getEmail(larkUserInfo)

	return &UserInfo{
		DisplayName: larkUserInfo.Data.Name,
		Username:    fmt.Sprintf("lark-%s", userId),
		Email:       email,
		AvatarUrl:   larkUserInfo.Data.AvatarUrl,
		Extra: map[string]string{
			"larkUnionId": larkUserInfo.Data.UnionId,
			"larkOpenId":  larkUserInfo.Data.OpenId,
			"larkUserId":  larkUserInfo.Data.UserId,
		},
	}, nil
}

func (idp *LarkIdProvider) getUserId(userInfo LarkUserInfo) string {
	switch idp.UserIdType {
	case "union_id":
		return userInfo.Data.UnionId
	case "open_id":
		return userInfo.Data.OpenId
	case "user_id":
		return userInfo.Data.UserId
	default:
		return ""
	}
}

func (idp *LarkIdProvider) getEmail(userInfo LarkUserInfo) string {
	if userInfo.Data.EnterpriseEmail != "" {
		return userInfo.Data.EnterpriseEmail
	}
	return userInfo.Data.Email
}

func (idp *LarkIdProvider) postWithBody(body interface{}, url string) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := idp.Client.Post(url, "application/json;charset=UTF-8", strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
