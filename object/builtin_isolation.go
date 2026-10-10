package object

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
)

func mayUseOrganizationMasterPassword(user *User) bool {
	return !conf.BuiltinIsolationEnabled() || user == nil || user.Owner != "built-in" || !conf.IsBuiltinAdminID(user.Id)
}

// IsOrganizationAdmin is for Casdoor administration, not business role claims.
func (user *User) IsOrganizationAdmin() bool {
	if user == nil {
		return false
	}
	if conf.BuiltinIsolationEnabled() && user.Owner == "built-in" {
		return !user.IsDeleted && !user.IsForbidden && user.builtinServiceIdentity
	}
	return user.IsAdmin
}

func IsBuiltinProvisioner(application *Application) bool {
	return conf.BuiltinProvisioningEnabled() && application != nil &&
		application.Owner == "admin" && application.Name == "app-built-in" &&
		application.Organization == "built-in" && !application.IsShared &&
		!application.IsDynamicClient() && !application.DisableSignin
}

// Startup reads existing identities only; no default administrator is inferred.
func ValidateBuiltinIsolationIdentities() error {
	if !conf.BuiltinIsolationEnabled() {
		return nil
	}
	ids, err := conf.BuiltinAdminIDs()
	if err != nil {
		return err
	}
	for _, id := range ids {
		users := []*User{}
		if err := ormer.Engine.Select("owner,id,is_deleted,is_forbidden").Where("id = ?", id).Find(&users); err != nil {
			return err
		}
		if len(users) != 1 || users[0].Owner != "built-in" || users[0].IsDeleted || users[0].IsForbidden {
			return fmt.Errorf("builtin administrator ID must identify exactly one active existing built-in user")
		}
	}
	return nil
}

// RestrictedBuiltinServiceAPI bounds machine credentials before general API policy.
func RestrictedBuiltinServiceAPI(method, path, owner string) bool {
	if owner != "built-in" {
		return false
	}
	if method == "GET" {
		switch path {
		case "/api/get-user", "/api/get-role", "/api/get-roles":
			return true
		}
	}
	return method == "POST" && (path == "/api/add-user" || path == "/api/update-user")
}

func ValidateBuiltinProvisionedUser(application *Application, user *User) error {
	if !IsBuiltinProvisioner(application) || user == nil || user.Owner != "built-in" ||
		user.Name == "" || user.Name == "admin" || strings.Contains(user.Name, "/") ||
		user.SignupApplication != "app-built-in" {
		return fmt.Errorf("restricted builtin provisioning requires the exact application and ordinary user")
	}
	if user.Tag != "" && user.Tag != "staff" {
		return fmt.Errorf("restricted builtin provisioning rejects privilege-bearing tags")
	}
	if user.Type != "" && user.Type != "normal-user" {
		return fmt.Errorf("restricted builtin provisioning requires an ordinary user type")
	}
	for key, value := range user.Properties {
		if !builtinBusinessPropertyAllowed(key, value) {
			return fmt.Errorf("restricted builtin provisioning rejects custom authority properties")
		}
	}
	allowed := map[string]bool{"Owner": true, "Name": true, "CreatedTime": true,
		"DisplayName": true, "Avatar": true, "Phone": true, "CountryCode": true,
		"Tag": true, "Type": true, "WeChat": true, "SignupApplication": true, "Properties": true}
	v := reflect.ValueOf(*user)
	for i := 0; i < v.NumField(); i++ {
		if !allowed[v.Type().Field(i).Name] && !v.Field(i).IsZero() {
			// Old SDKs serialize empty slices/maps; these carry no authority.
			if (v.Field(i).Kind() == reflect.Slice || v.Field(i).Kind() == reflect.Map) && v.Field(i).Len() == 0 {
				continue
			}
			return fmt.Errorf("restricted builtin provisioning rejects field %s", v.Type().Field(i).Name)
		}
	}
	return nil
}

func builtinBusinessPropertyAllowed(key, value string) bool {
	if key == UserPropertiesWechatOpenId || key == UserPropertiesWechatUnionId {
		return true
	}
	if key != "registerPlatform" {
		return false
	}
	return util.InSlice([]string{"snailpet", "cyj_app", "cyj_mp", "cyj_supply_chain", "cyj_brand", "cyj_mp_finclip", "cyj_supply_chain_finclip", "cyj_brand_finclip", "cyj_online_show_finclip", "cyj_oms_finclip", "cyj_recruit_seeker_finclip", "cyj_recruit_employer_finclip", "cxy_xiaoe_tech", "oms"}, value)
}

// MP's existing DTO omits countryCode. Only a valid mainland mobile may infer CN.
func NormalizeBuiltinProvisionedPhone(user *User) {
	if user.CountryCode == "" && len(user.Phone) == 11 && strings.HasPrefix(user.Phone, "1") {
		phone, country, ok := util.GetNormalizedPhone(user.Phone, "CN")
		if ok && country == "CN" {
			user.Phone, user.CountryCode = phone, country
		}
	}
}

func AddBuiltinUserFromService(application *Application, user *User, lang string) (bool, error) {
	if err := ValidateBuiltinProvisionedUser(application, user); err != nil {
		return false, err
	}
	user.RegisterType, user.RegisterSource = "Restricted service", application.GetId()
	return addUser(user, lang, true)
}

// Updating profiles cannot rename/promote an identity or edit an administrator.
// The legacy SDK submits the whole user together with an explicit column list.
func ValidateBuiltinServiceUserUpdate(oldUser, user *User, columns string) error {
	if oldUser == nil || user == nil || oldUser.Owner != "built-in" ||
		oldUser.Name == "admin" || conf.IsBuiltinAdminID(oldUser.Id) ||
		user.Owner != oldUser.Owner || user.Name != oldUser.Name || user.Id != oldUser.Id || columns == "" {
		return fmt.Errorf("restricted builtin service cannot update this identity")
	}
	allowed := map[string]bool{"phone": true, "country_code": true, "countryCode": true,
		"avatar": true, "display_name": true, "displayName": true, "external_id": true, "externalId": true}
	for _, col := range strings.Split(columns, ",") {
		if !allowed[col] {
			return fmt.Errorf("restricted builtin service cannot update column %s", col)
		}
	}
	if (util.InSlice(strings.Split(columns, ","), "external_id") || util.InSlice(strings.Split(columns, ","), "externalId")) && user.ExternalId != oldUser.ExternalId && (oldUser.ExternalId != "" || user.ExternalId != oldUser.Id) {
		return fmt.Errorf("restricted builtin service can only initialize externalId to the existing stable ID")
	}
	return nil
}

func PrepareBuiltinServiceUserUpdate(oldUser, submitted *User, columns string) (*User, error) {
	// Java SDK 1.22's WeChat binding submits a full object without columns.
	// Turn it into an explicit projection; never use UpdateUser's default fields.
	if columns == "" {
		columns = "phone,country_code,avatar,display_name"
		if oldUser != nil && submitted != nil && submitted.CountryCode == "" {
			submitted.CountryCode = oldUser.CountryCode
		}
		if err := ValidateBuiltinServiceUserUpdate(oldUser, submitted, columns); err != nil {
			return nil, err
		}
		next := *oldUser
		next.Phone, next.CountryCode, next.Avatar, next.DisplayName = submitted.Phone, submitted.CountryCode, submitted.Avatar, submitted.DisplayName
		next.WeChat = submitted.WeChat
		next.Properties = map[string]string{}
		for key, value := range oldUser.Properties {
			next.Properties[key] = value
		}
		for key, value := range submitted.Properties {
			if !builtinBusinessPropertyAllowed(key, value) {
				if oldUser.Properties[key] != value {
					return nil, fmt.Errorf("restricted builtin service rejects changed property %s", key)
				}
				continue
			}
			next.Properties[key] = value
		}
		return &next, nil
	}
	if err := ValidateBuiltinServiceUserUpdate(oldUser, submitted, columns); err != nil {
		return nil, err
	}
	// Ignore the old SDK's echoed password/roles/metadata before validation and
	// UpdateUser's derived writes (hash, guest promotion, deleted_time).
	next := *oldUser
	for _, col := range strings.Split(columns, ",") {
		switch col {
		case "phone":
			next.Phone = submitted.Phone
		case "country_code", "countryCode":
			next.CountryCode = submitted.CountryCode
		case "avatar":
			next.Avatar = submitted.Avatar
		case "display_name", "displayName":
			next.DisplayName = submitted.DisplayName
		case "external_id", "externalId":
			next.ExternalId = submitted.ExternalId
		}
	}
	return &next, nil
}
