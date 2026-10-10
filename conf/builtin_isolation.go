package conf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// A nonempty invalid switch is restrictive until startup validation rejects it.
func BuiltinIsolationEnabled() bool {
	v := GetConfigString("CASDOOR_BUILTIN_ISOLATION_ENABLED")
	return v != "" && v != "false"
}

func BuiltinAdminIDs() ([]string, error) {
	var ids []string
	if err := json.Unmarshal([]byte(GetConfigString("CASDOOR_BUILTIN_ADMIN_IDS")), &ids); err != nil {
		return nil, fmt.Errorf("CASDOOR_BUILTIN_ADMIN_IDS must be a JSON array of stable user IDs")
	}
	if len(ids) == 0 || len(ids) > 64 {
		return nil, fmt.Errorf("builtin administrator list must contain 1 to 64 stable user IDs")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id || strings.ContainsAny(id, "/*,\r\n\t ") || seen[id] {
			return nil, fmt.Errorf("builtin administrator list contains an invalid or duplicate ID")
		}
		seen[id] = true
	}
	return ids, nil
}

func IsBuiltinAdminID(id string) bool {
	ids, err := BuiltinAdminIDs()
	if err != nil || id == "" {
		return false
	}
	for _, allowed := range ids {
		if id == allowed {
			return true
		}
	}
	return false
}

func BuiltinProvisioningEnabled() bool {
	return BuiltinIsolationEnabled() && GetConfigString("CASDOOR_BUILTIN_PROVISIONER_APPLICATION") == "admin/app-built-in"
}

func ValidateBuiltinIsolationConfig() error {
	switch GetConfigString("CASDOOR_BUILTIN_ISOLATION_ENABLED") {
	case "", "false":
		if GetConfigString("CASDOOR_BUILTIN_PROVISIONER_APPLICATION") != "" {
			return fmt.Errorf("builtin provisioning requires builtin isolation")
		}
		return nil
	case "true":
	default:
		return fmt.Errorf("CASDOOR_BUILTIN_ISOLATION_ENABLED must be true or false")
	}
	if _, err := BuiltinAdminIDs(); err != nil {
		return err
	}
	app := GetConfigString("CASDOOR_BUILTIN_PROVISIONER_APPLICATION")
	if app != "" && app != "admin/app-built-in" {
		return fmt.Errorf("builtin provisioner must be admin/app-built-in")
	}
	return nil
}
