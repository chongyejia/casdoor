package object

import (
	"context"
	"encoding/base64"
	"math"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xorm-io/xorm"
)

func cleanupTestRefresh(t *testing.T, exp *time.Time) string {
	t.Helper()
	claims := jwt.RegisteredClaims{}
	if exp != nil {
		claims.ExpiresAt = jwt.NewNumericDate(*exp)
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("synthetic-cleanup-key"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTokenCleanupRefreshEligibility(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	future, past := now.Add(55*24*time.Hour), now.Add(-time.Second)
	base := Token{CreatedTime: now.Add(-35 * 24 * time.Hour).Format(time.RFC3339), ExpiresIn: 3600}
	rows := []struct {
		name, refresh, hash string
		ttl                 int
		want                bool
	}{
		{"live-refresh-old-access", cleanupTestRefresh(t, &future), "", 3600, false},
		{"expired-refresh", cleanupTestRefresh(t, &past), "", 3600, true},
		{"refresh-at-boundary", cleanupTestRefresh(t, &now), "", 3600, false},
		{"missing-exp", cleanupTestRefresh(t, nil), "", 3600, false},
		{"historical-opaque", "synthetic-opaque", "", 3600, false},
		{"hash-only", "", "synthetic-hash", 3600, false},
		{"no-refresh", "", "", 3600, true},
		{"revoked-live-refresh", cleanupTestRefresh(t, &future), "", 0, true},
		{"revoked-unknown", "synthetic-opaque", "", 0, true},
		{"live-access", "", "", 40 * 24 * 3600, false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.RefreshToken = tc.refresh
			r.RefreshTokenHash = tc.hash
			r.ExpiresIn = tc.ttl
			if got := tokenCleanupEligible(&r, now, 30*24*3600); got != tc.want {
				t.Fatalf("eligible=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestTokenCleanupInvalidTimesAndRetention(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	r := Token{CreatedTime: now.Add(-31 * 24 * time.Hour).Format(time.RFC3339), ExpiresIn: 24 * 3600}
	if tokenCleanupEligible(&r, now, 30*24*3600) {
		t.Fatal("retention boundary must retain")
	}
	if !tokenCleanupEligible(&r, now.Add(time.Second), 30*24*3600) {
		t.Fatal("past retention must expire")
	}
	for _, stamp := range []string{"", "not-a-time", now.Add(time.Hour).Format(time.RFC3339)} {
		r.CreatedTime = stamp
		if tokenCleanupEligible(&r, now, 1) {
			t.Fatal("unknown or future timestamp deleted")
		}
	}
	r.CreatedTime = now.Add(-35 * 24 * time.Hour).Format(time.RFC3339)
	r.ExpiresIn = math.MaxInt64
	if tokenCleanupEligible(&r, now, 1) {
		t.Fatal("overflow TTL deleted")
	}
	r.ExpiresIn = 1
	if tokenCleanupEligible(&r, now, math.MaxInt64) || tokenCleanupEligible(&r, now, -1) || tokenCleanupEligible(nil, now, 1) {
		t.Fatal("invalid retention or nil deleted")
	}
}

func TestTokenCleanupSQLitePreservesRefreshAndPages(t *testing.T) {
	engine, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMaxOpenConns(1)
	previous := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: engine}
	t.Cleanup(func() { ormer = previous; engine.Close() })
	if err := engine.Sync2(new(Token)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Exec("CREATE TABLE organization (owner TEXT, name TEXT, token_retention_days INTEGER, created_time TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Exec("INSERT INTO organization VALUES ('admin','synthetic-org',1,'2026-10-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Exec("CREATE TABLE preserved_policy (id INTEGER, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Exec("INSERT INTO preserved_policy VALUES (1,'unchanged')"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	future := now.Add(55 * 24 * time.Hour)
	live := Token{Owner: "synthetic", Name: "a-live-refresh", Organization: "synthetic-org", CreatedTime: now.Add(-35 * 24 * time.Hour).Format(time.RFC3339), ExpiresIn: 3600, RefreshToken: cleanupTestRefresh(t, &future)}
	revoked := live
	revoked.Name = "b-revoked"
	revoked.ExpiresIn = 0
	recent := live
	recent.Name = "c-retention"
	recent.RefreshToken = ""
	recent.CreatedTime = now.Add(-12 * time.Hour).Format(time.RFC3339)
	unknown := live
	unknown.Name = "d-unknown"
	unknown.RefreshToken = "synthetic-opaque"
	for _, r := range []*Token{&live, &revoked, &recent, &unknown} {
		if _, err := engine.Insert(r); err != nil {
			t.Fatal(err)
		}
	}
	// Cross a primary-key page boundary; retained rows must not prevent progress.
	for i := 0; i < tokenCleanupBatchSize+1; i++ {
		r := Token{Owner: "synthetic", Name: time.Unix(int64(i), 0).UTC().Format("20060102150405"), Organization: "synthetic-org", CreatedTime: live.CreatedTime, ExpiresIn: 3600}
		if _, err := engine.Insert(&r); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupTokensAt(now); err != nil {
		t.Fatal(err)
	}
	count, err := engine.Count(new(Token))
	if err != nil || count != 5 {
		t.Fatalf("per-run delete bound lost: remaining=%d err=%v", count, err)
	}
	if err := cleanupTokensAt(now); err != nil {
		t.Fatal(err)
	}
	var got []Token
	if err := engine.Asc("name").Find(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != live.Name || got[1].Name != recent.Name || got[2].Name != unknown.Name {
		t.Fatalf("unexpected retained row count/names, count=%d", len(got))
	}
	rows, err := engine.QueryString("SELECT value FROM preserved_policy WHERE id=1")
	if err != nil || len(rows) != 1 || rows[0]["value"] != "unchanged" {
		t.Fatal("unrelated policy changed")
	}
}

func TestTokenCleanupUnsafeRefreshMetadata(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	row := Token{CreatedTime: now.Add(-35 * 24 * time.Hour).Format(time.RFC3339), ExpiresIn: 3600}
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, raw := range []string{`1e100`, `9223372036854775808`, `253402300800`, `-1`, `"1"`, `1.1`, `null`, `{}`, `[]`} {
		row.RefreshToken = enc(`{"alg":"HS256"}`) + "." + enc(`{"exp":`+raw+`}`) + "." + enc("synthetic")
		if tokenCleanupEligible(&row, now, 30*24*3600) {
			t.Fatalf("unsafe exp accepted: %s", raw)
		}
	}
	for _, payload := range []string{`{"exp":1}{"exp":9999999999}`, `{"exp":1}garbage`} {
		row.RefreshToken = enc(`{"alg":"HS256"}`) + "." + enc(payload) + "." + enc("synthetic")
		if tokenCleanupEligible(&row, now, 30*24*3600) {
			t.Fatal("trailing JSON content deleted")
		}
	}
	row.RefreshToken = enc(`{"alg":"HS256"}`) + "." + enc("{\"exp\":1} \n\t") + "." + enc("synthetic")
	if !tokenCleanupEligible(&row, now, 30*24*3600) {
		t.Fatal("valid trailing whitespace rejected")
	}
	past := now.Add(-time.Second)
	row.RefreshToken = cleanupTestRefresh(t, &past)
	row.RefreshTokenHash = "different-lookup-hash"
	if tokenCleanupEligible(&row, now, 30*24*3600) {
		t.Fatal("raw/hash mismatch deleted")
	}
	row.RefreshTokenHash = getTokenHash(row.RefreshToken)
	if !tokenCleanupEligible(&row, now, 30*24*3600) {
		t.Fatal("matching expired refresh retained")
	}
	row.CreatedTime = "0001-01-01T00:00:00Z"
	if tokenCleanupEligible(&row, now, 1) {
		t.Fatal("zero timestamp deleted")
	}
	if getTokenRetentionInterval(math.MaxInt64) != -1 {
		t.Fatal("huge days must preserve rather than overflow")
	}
	for _, days := range []int{0, -1, 30} {
		if getTokenRetentionInterval(days) != 30*24*3600 {
			t.Fatal("default retention changed")
		}
	}
}

func TestTokenCleanupConditionalDelete(t *testing.T) {
	e, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	e.SetMaxOpenConns(1)
	prev := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: e}
	t.Cleanup(func() { ormer = prev; e.Close() })
	if err = e.Sync2(new(Token)); err != nil {
		t.Fatal(err)
	}
	base := Token{Owner: "Owner", Name: "same-key", Organization: "synthetic", CreatedTime: "2026-01-01T00:00:00Z", ExpiresIn: 3600, RefreshToken: "opaque-old", RefreshTokenHash: "hash-old", AccessToken: "access-old", AccessTokenHash: "ahash-old", Application: "app-old"}
	changes := []struct {
		column string
		value  interface{}
	}{
		{"owner", "owner"}, {"name", "SAME-key"}, {"organization", "SYNTHETIC"}, {"created_time", "2026-01-02T00:00:00Z"}, {"expires_in", 7200},
		{"refresh_token", "opaque-OLD"}, {"refresh_token_hash", "hash-OLD"}, {"application", "APP-old"}, {"access_token", "access-OLD"}, {"access_token_hash", "ahash-OLD"},
	}
	for _, c := range changes {
		t.Run(c.column, func(t *testing.T) {
			if _, err := e.Exec("DELETE FROM token"); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Insert(&base); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Exec("UPDATE token SET "+c.column+" = ?", c.value); err != nil {
				t.Fatal(err)
			}
			affected, err := deleteTokenCleanupSnapshot(&base)
			if err != nil || affected != 0 {
				t.Fatalf("changed row deleted: affected=%d err=%v", affected, err)
			}
			count, err := e.Count(new(Token))
			if err != nil || count != 1 {
				t.Fatal("replacement row lost")
			}
		})
	}
	if _, err = e.Exec("DELETE FROM token"); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Insert(&base); err != nil {
		t.Fatal(err)
	}
	affected, err := deleteTokenCleanupSnapshot(&base)
	if err != nil || affected != 1 {
		t.Fatalf("unchanged row not deleted: %d %v", affected, err)
	}
	affected, err = deleteTokenCleanupSnapshot(&base)
	if err != nil || affected != 0 {
		t.Fatal("already-deleted row not idempotent")
	}
	nullRow := Token{Owner: "synthetic", Name: "null-fields", CreatedTime: "2026-01-01T00:00:00Z"}
	if _, err = e.Insert(&nullRow); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Exec("UPDATE token SET organization=NULL, refresh_token=NULL, refresh_token_hash=NULL, expires_in=NULL, application=NULL, access_token=NULL, access_token_hash=NULL"); err != nil {
		t.Fatal(err)
	}
	affected, err = deleteTokenCleanupSnapshot(&nullRow)
	if err != nil || affected != 1 {
		t.Fatalf("legacy NULL empty equivalence failed: %d %v", affected, err)
	}
	if _, err = e.Exec("DROP TABLE token"); err != nil {
		t.Fatal(err)
	}
	if _, err = deleteTokenCleanupSnapshot(&base); err == nil {
		t.Fatal("SQL failure ignored")
	}
}

func TestTokenCleanupRunBounds(t *testing.T) {
	e, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	e.SetMaxOpenConns(1)
	prev := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: e}
	t.Cleanup(func() { ormer = prev; e.Close() })
	if err = e.Sync2(new(Token)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Exec("CREATE TABLE organization (owner TEXT, name TEXT, token_retention_days INTEGER)"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	future := now.Add(55 * 24 * time.Hour)
	base := Token{Owner: "synthetic", CreatedTime: now.Add(-35 * 24 * time.Hour).Format(time.RFC3339), ExpiresIn: 3600, RefreshToken: cleanupTestRefresh(t, &future)}
	for _, n := range []string{"a", "b", "c", "d"} {
		r := base
		r.Name = n
		if n == "d" {
			r.RefreshToken = ""
		}
		if _, err = e.Insert(&r); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupTokensLimitedAt(now, 1, 2); err != nil {
		t.Fatal(err)
	}
	n, err := e.Count(new(Token))
	if err != nil || n != 4 {
		t.Fatal("scan cap ignored")
	}
	if err := cleanupTokensLimitedAt(now, 1, 4); err != nil {
		t.Fatal(err)
	}
	n, err = e.Count(new(Token))
	if err != nil || n != 3 {
		t.Fatal("larger bounded scan did not reach old row")
	}
	snapshot := base
	snapshot.Name = "a"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := deleteTokenCleanupSnapshotContext(ctx, &snapshot); err == nil {
		t.Fatal("cancelled cleanup query ran")
	}
	n, err = e.Count(new(Token))
	if err != nil || n != 3 {
		t.Fatal("cancelled request changed data")
	}
	if err := cleanupTokensLimitedAt(now, 0, 1); err == nil {
		t.Fatal("zero delete budget accepted")
	}
}
