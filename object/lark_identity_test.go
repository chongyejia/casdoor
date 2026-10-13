package object

import "testing"

func TestTypedLarkIdentityEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, kind, value string
		user              *User
		want              bool
	}{
		{"legacy ordinary", "user_id", "synthetic-user", &User{Lark: "synthetic-user", Properties: map[string]string{"oauth_Lark_extra": `{"larkUserId":"synthetic-user","larkOpenId":"synthetic-open","larkAppId":"app-A","larkTenantKey":"tenant-A"}`}}, true},
		{"wrong ID type", "open_id", "synthetic-user", &User{Lark: "synthetic-user", Properties: map[string]string{"oauth_Lark_extra": `{"larkUserId":"synthetic-user","larkOpenId":"synthetic-open","larkAppId":"app-A","larkTenantKey":"tenant-A"}`}}, false},
		{"legacy mini program", "union_id", "synthetic-union", &User{Lark: "synthetic-union", Properties: map[string]string{"larkUnionId": "synthetic-union", "larkAppId": "app-A", "larkTenantKey": "tenant-A"}}, true},
		{"untyped row", "user_id", "synthetic-user", &User{Lark: "synthetic-user"}, false},
		{"wrong selected value", "user_id", "synthetic-user", &User{Lark: "synthetic-user", Properties: map[string]string{"larkUserId": "another-user"}}, false},
		{"conflicting saved type", "user_id", "synthetic-user", &User{Lark: "synthetic-user", Properties: map[string]string{"larkUserId": "synthetic-user", "larkAppId": "app-A", "larkTenantKey": "tenant-A", "larkIdType": "open_id"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesTypedLarkIdentity(tc.user, tc.kind, tc.value, "app-A", "tenant-A"); got != tc.want {
				t.Fatalf("match=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestTypedLarkUserSelectionRejectsAmbiguityAndCrossOwner(t *testing.T) {
	a := &User{Owner: "owner-a", Lark: "same-id", Properties: map[string]string{"larkUserId": "same-id", "larkAppId": "app-A", "larkTenantKey": "tenant-A"}}
	b := &User{Owner: "owner-a", Lark: "same-id", Properties: map[string]string{"larkUserId": "same-id", "larkAppId": "app-A", "larkTenantKey": "tenant-A"}}
	if _, err := chooseTypedLarkUser([]*User{a, b}, "owner-a", "user_id", "same-id", "app-A", "tenant-A"); err == nil {
		t.Fatal("duplicate account matches must be rejected")
	}
	if _, err := chooseTypedLarkUser([]*User{a}, "owner-b", "user_id", "same-id", "app-A", "tenant-A"); err == nil {
		t.Fatal("cross-owner account must be rejected")
	}
	if got, err := chooseTypedLarkUser([]*User{a}, "owner-a", "user_id", "same-id", "app-A", "tenant-A"); err != nil || got != a {
		t.Fatalf("unique typed match rejected: account=%p, err=%v", got, err)
	}
	a.IsForbidden = true
	if _, err := chooseTypedLarkUser([]*User{a}, "owner-a", "user_id", "same-id", "app-A", "tenant-A"); err == nil {
		t.Fatal("forbidden account must not be used or recreated")
	}
	a.IsForbidden = false
	a.IsDeleted = true
	if _, err := chooseTypedLarkUser([]*User{a}, "owner-a", "user_id", "same-id", "app-A", "tenant-A"); err == nil {
		t.Fatal("deleted account must not be used or recreated")
	}
}
