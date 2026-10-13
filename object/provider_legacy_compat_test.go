package object

import (
	"encoding/json"
	"testing"
)

func TestLegacyLarkUserIdTypeSurvivesProviderConversion(t *testing.T) {
	var provider Provider
	if err := json.Unmarshal([]byte(`{"owner":"lab","name":"lark-test","type":"Lark","userIdType":"user_id"}`), &provider); err != nil {
		t.Fatal(err)
	}
	info, err := FromProviderToIdpInfo(nil, &provider)
	if err != nil {
		t.Fatal(err)
	}
	if info.UserIdType != "user_id" {
		t.Fatalf("lost legacy Lark selector: %q", info.UserIdType)
	}
	encoded, err := json.Marshal(provider)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip map[string]any
	if err = json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip["userIdType"] != "user_id" {
		t.Fatalf("lost legacy Lark selector in JSON: %v", roundtrip["userIdType"])
	}
}
