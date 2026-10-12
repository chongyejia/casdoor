// Copyright 2025 The Casdoor Authors. All Rights Reserved.
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

package object

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/robfig/cron/v3"
)

const (
	defaultTokenRetentionDays      = 30
	tokenCleanupBatchSize          = 1000
	maxTokenCleanupDurationSeconds = int64(1<<63-1) / int64(time.Second)
	tokenCleanupMaxDeletes         = 1000
	tokenCleanupMaxScanned         = 10000
	tokenCleanupRunTimeout         = 15 * time.Second
)

// getTokenRetentionInterval converts a retention period in days into seconds,
// falling back to the default when the configured value is non-positive.
func getTokenRetentionInterval(days int) int {
	if days <= 0 {
		days = defaultTokenRetentionDays
	}
	// An unrepresentable retention period must not wrap into an early cutoff.
	if int64(days) > maxTokenCleanupDurationSeconds/(24*3600) {
		return -1
	}
	return days * 24 * 3600
}

// getOrgTokenRetentionIntervals returns a map from organization name to its
// configured token retention interval (in seconds), so that each organization
// can control how long its expired tokens are kept before cleanup.
func getOrgTokenRetentionIntervals(ctx context.Context) (map[string]int, error) {
	organizations := []*Organization{}
	err := ormer.Engine.Context(ctx).Cols("name", "token_retention_days").Find(&organizations, &Organization{Owner: "admin"})
	if err != nil {
		return nil, fmt.Errorf("failed to load organizations for token cleanup: %w", err)
	}

	intervals := make(map[string]int, len(organizations))
	for _, organization := range organizations {
		intervals[organization.Name] = getTokenRetentionInterval(organization.TokenRetentionDays)
	}
	return intervals, nil
}

func CleanupTokens() error {
	return cleanupTokensAt(time.Now())
}

func cleanupTokensAt(currentTime time.Time) error {
	return cleanupTokensLimitedAt(currentTime, tokenCleanupMaxDeletes, tokenCleanupMaxScanned)
}

// Cleanup is best effort. Bounds favor retaining historical rows over competing
// with login traffic; reaching a limit does not mean all history was reclaimed.
func cleanupTokensLimitedAt(currentTime time.Time, maxDeletes, maxScanned int) error {
	if maxDeletes <= 0 || maxScanned <= 0 {
		return fmt.Errorf("invalid token cleanup limits")
	}
	ctx, cancel := context.WithTimeout(context.Background(), tokenCleanupRunTimeout)
	defer cancel()
	orgIntervals, err := getOrgTokenRetentionIntervals(ctx)
	if err != nil {
		return err
	}

	// Use the smallest retention interval (across all organizations) to compute the
	// query cutoff, so that no token eligible for cleanup under any organization's
	// setting is missed. A token can only be eligible if it was created before this
	// cutoff, since createdTime + expiresIn (the token's expiry) must be even earlier
	// than that for it to have been expired for longer than the retention interval.
	minInterval := getTokenRetentionInterval(defaultTokenRetentionDays)
	for _, interval := range orgIntervals {
		if interval >= 0 && interval < minInterval {
			minInterval = interval
		}
	}
	cutoffTime := currentTime.Add(-time.Duration(minInterval) * time.Second).Format(time.RFC3339)

	defaultInterval := getTokenRetentionInterval(defaultTokenRetentionDays)

	// Walk the tokens in primary key order, so that a huge token table is never loaded into memory at once.
	lastOwner, lastName := "", ""
	scanned, deleted := 0, 0
	for scanned < maxScanned {
		sessions := []*Token{}
		query := ormer.Engine.Context(ctx).Where("created_time < ?", cutoffTime)
		if lastOwner != "" || lastName != "" {
			query = query.And("(owner > ? or (owner = ? and name > ?))", lastOwner, lastOwner, lastName)
		}

		pageSize := min(tokenCleanupBatchSize, maxScanned-scanned)
		err = query.Asc("owner", "name").Limit(pageSize).Find(&sessions)
		if err != nil {
			return fmt.Errorf("failed to query expired tokens: %w", err)
		}
		if len(sessions) == 0 {
			break
		}

		scanned += len(sessions)
		for _, session := range sessions {
			retentionInterval, ok := orgIntervals[session.Organization]
			if !ok {
				// The token's organization no longer exists (or has no configured value);
				// fall back to the default retention period.
				retentionInterval = defaultInterval
			}

			if !tokenCleanupEligible(session, currentTime, retentionInterval) {
				continue
			}
			affected, err := deleteTokenCleanupSnapshotContext(ctx, session)
			if err != nil {
				return fmt.Errorf("failed to delete expired token: %w", err)
			}
			deleted += int(affected) // A changed/already removed snapshot contributes zero.
			if deleted >= maxDeletes {
				return nil
			}
		}

		lastSession := sessions[len(sessions)-1]
		lastOwner, lastName = lastSession.Owner, lastSession.Name
		if len(sessions) < pageSize {
			break
		}
	}

	return nil
}

// tokenCleanupEligible uses refresh expiry only to retain potentially usable
// sessions, never to authenticate a token. The refresh grant still performs its
// normal database revocation and signature checks. Unknown historical formats
// are retained; cleanup must not turn incomplete metadata into revocation.
func tokenCleanupEligible(token *Token, now time.Time, retentionSeconds int) bool {
	if token == nil || retentionSeconds < 0 || int64(retentionSeconds) > maxTokenCleanupDurationSeconds || (int64(token.ExpiresIn) > maxTokenCleanupDurationSeconds || int64(token.ExpiresIn) < -maxTokenCleanupDurationSeconds) {
		return false
	}
	created, err := time.Parse(time.RFC3339, token.CreatedTime)
	if err != nil || created.IsZero() {
		return false
	}
	expiresIn := token.ExpiresIn
	if expiresIn < 0 {
		expiresIn = 0
	}
	accessExpiry := created.Add(time.Duration(expiresIn) * time.Second)
	if !now.After(accessExpiry.Add(time.Duration(retentionSeconds) * time.Second)) {
		return false
	}
	if token.ExpiresIn <= 0 {
		return true // Explicitly revoked grants already reject refresh.
	}
	if token.RefreshToken == "" {
		return token.RefreshTokenHash == "" // Hash-only history is not proof of expiry.
	}
	if token.RefreshTokenHash != "" && token.RefreshTokenHash != getTokenHash(token.RefreshToken) {
		return false
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithJSONNumber())
	_, parts, err := parser.ParseUnverified(token.RefreshToken, claims)
	if err != nil || len(parts) != 3 {
		return false
	}
	payload, err := parser.DecodeSegment(parts[1])
	if err != nil || !json.Valid(payload) {
		return false
	}
	rawExpiry, ok := claims["exp"].(json.Number)
	if !ok {
		return false
	}
	expiry, err := rawExpiry.Int64()
	if err != nil || expiry < 0 || expiry > 253402300799 {
		return false
	}
	return now.After(time.Unix(expiry, 0))
}

// The normal refresh flow creates a new primary key. The management API can
// replace a row in place, so deletion also compares the scanned qualification
// fields byte for byte. A changed row is left for a later scan.
func deleteTokenCleanupSnapshot(token *Token) (int64, error) {
	return deleteTokenCleanupSnapshotContext(context.Background(), token)
}

func deleteTokenCleanupSnapshotContext(ctx context.Context, token *Token) (int64, error) {
	if token == nil {
		return 0, nil
	}
	query := ormer.Engine.Context(ctx).Where("owner = ? AND name = ?", token.Owner, token.Name)
	defer query.Close()
	fields := []struct{ name, value string }{
		{"owner", token.Owner}, {"name", token.Name}, {"organization", token.Organization},
		{"created_time", token.CreatedTime}, {"refresh_token", token.RefreshToken},
		{"refresh_token_hash", token.RefreshTokenHash}, {"application", token.Application},
		{"access_token", token.AccessToken}, {"access_token_hash", token.AccessTokenHash},
	}
	for _, field := range fields {
		var condition string
		switch ormer.driverName {
		case "mysql":
			condition = "BINARY " + field.name + " = BINARY ?"
		case "sqlite", "sqlite3":
			condition = "CAST(" + field.name + " AS BLOB) = CAST(? AS BLOB)"
		default:
			return 0, fmt.Errorf("token cleanup exact comparison unsupported for database driver")
		}
		if field.value == "" {
			condition = "(" + field.name + " IS NULL OR " + condition + ")"
		}
		query = query.And(condition, field.value)
	}
	if token.ExpiresIn == 0 {
		query = query.And("(expires_in IS NULL OR expires_in = 0)")
	} else {
		query = query.And("expires_in = ?", token.ExpiresIn)
	}
	return query.Delete(&Token{})
}

func InitCleanupTokens() {
	schedule := "0 0 * * *"

	go func() {
		if err := CleanupTokens(); err != nil {
			fmt.Printf("Error cleaning up tokens at startup: %v\n", err)
		}
	}()

	cronJob := cron.New()
	_, err := cronJob.AddFunc(schedule, func() {
		if err := CleanupTokens(); err != nil {
			fmt.Printf("Error cleaning up tokens: %v\n", err)
		}
	})
	if err != nil {
		fmt.Printf("Error scheduling token cleanup: %v\n", err)
		return
	}
	cronJob.Start()
}
