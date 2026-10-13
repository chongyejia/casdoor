package object

import (
	"strings"
	"testing"

	jsoniter "github.com/json-iterator/go"
)

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

func stubLarkPersist(t *testing.T) *int {
	calls := 0
	orig := persistLarkEvidence
	persistLarkEvidence = func(*User) error { calls++; return nil }
	t.Cleanup(func() { persistLarkEvidence = orig })
	return &calls
}

func TestTypedLarkUserBackfillsMissingEvidence(t *testing.T) {
	calls := stubLarkPersist(t)
	u := &User{Owner: "o", Name: "n", Lark: "uid", Properties: map[string]string{"oauth_Lark_extra": `{"larkOpenId":"ou_x","keep":"1"}`}}
	got, err := chooseTypedLarkUser([]*User{u}, "o", "user_id", "uid", "app-A", "tenant-A")
	if err != nil || got != u || *calls != 1 {
		t.Fatalf("got=%p err=%v calls=%d", got, err, *calls)
	}
	var extra map[string]string
	if err := jsoniter.Unmarshal([]byte(u.Properties["oauth_Lark_extra"]), &extra); err != nil {
		t.Fatal(err)
	}
	if extra["larkUserId"] != "uid" || extra["larkAppId"] != "app-A" || extra["larkTenantKey"] != "tenant-A" || extra["larkIdType"] != "user_id" || extra["keep"] != "1" || extra["larkOpenId"] != "ou_x" {
		t.Fatalf("bad extra %v", extra)
	}
	if !matchesTypedLarkIdentity(u, "user_id", "uid", "app-A", "tenant-A") {
		t.Fatal("backfilled user should now match")
	}
	// No properties at all is also accepted.
	v := &User{Owner: "o", Name: "m", Lark: "uid2"}
	if _, err := chooseTypedLarkUser([]*User{v}, "o", "user_id", "uid2", "app-A", "tenant-A"); err != nil || *calls != 2 {
		t.Fatalf("err=%v calls=%d", err, *calls)
	}
}

func TestTypedLarkUserRejectsConflictingEvidence(t *testing.T) {
	calls := stubLarkPersist(t)
	for name, props := range map[string]map[string]string{
		"app id":        {"oauth_Lark_extra": `{"larkAppId":"app-B"}`},
		"tenant":        {"oauth_Lark_extra": `{"larkTenantKey":"tenant-B"}`},
		"direct tenant": {"larkTenantKey": "tenant-B"},
		"id type":       {"oauth_Lark_extra": `{"larkIdType":"open_id"}`},
		"typed key":     {"oauth_Lark_extra": `{"larkUserId":"ou_other"}`},
		"bad json":      {"oauth_Lark_extra": `{`},
	} {
		u := &User{Owner: "o", Name: "n", Lark: "uid", Properties: props}
		if _, err := chooseTypedLarkUser([]*User{u}, "o", "user_id", "uid", "app-A", "tenant-A"); err == nil || !strings.Contains(err.Error(), "typed identity evidence") {
			t.Fatalf("%s: expected evidence error, got %v", name, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("conflicts must not persist, calls=%d", *calls)
	}
}

func TestTypedLarkUserFullMatchAndMultipleUnchanged(t *testing.T) {
	calls := stubLarkPersist(t)
	full := &User{Owner: "o", Lark: "uid", Properties: map[string]string{"oauth_Lark_extra": `{"larkUserId":"uid","larkAppId":"app-A","larkTenantKey":"tenant-A"}`}}
	if got, err := chooseTypedLarkUser([]*User{full}, "o", "user_id", "uid", "app-A", "tenant-A"); err != nil || got != full {
		t.Fatalf("full match rejected: %v", err)
	}
	a, b := &User{Owner: "o", Lark: "uid"}, &User{Owner: "o", Lark: "uid"}
	if _, err := chooseTypedLarkUser([]*User{a, b}, "o", "user_id", "uid", "app-A", "tenant-A"); err == nil {
		t.Fatal("multiple matches must stay ambiguous")
	}
	if got, err := chooseTypedLarkUser(nil, "o", "user_id", "uid", "app-A", "tenant-A"); got != nil || err != nil {
		t.Fatal("zero match must stay nil,nil")
	}
	inactive := &User{Owner: "o", Lark: "uid", IsForbidden: true}
	if _, err := chooseTypedLarkUser([]*User{inactive}, "o", "user_id", "uid", "app-A", "tenant-A"); err == nil {
		t.Fatal("inactive must be rejected")
	}
	if *calls != 0 {
		t.Fatalf("no backfill expected, calls=%d", *calls)
	}
}
