package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeCodexPrivacyKeyUppercaseIDAliases(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"deviceID", "device_id"},
		{"installationID", "installation_id"},
		{"sessionID", "session_id"},
		{"threadID", "thread_id"},
		{"turnID", "turn_id"},
		{"windowID", "window_id"},
		{"conversationID", "conversation_id"},
		{"previousResponseID", "previous_response_id"},
		{"responsesAPIClientMetadata", "responsesapi_client_metadata"},
	} {
		if got := normalizeCodexPrivacyKey(tc.input); got != tc.want {
			t.Errorf("normalizeCodexPrivacyKey(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSanitizeCodexPrivacyRequestBodyDropsUppercaseIDAliases(t *testing.T) {
	account := &Account{
		ID:       43,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{codexFingerprintModeExtraKey: string(codexFingerprintSession)},
	}
	ids := &codexFingerprintIDs{
		installationID:        "installation",
		sessionID:             "session",
		threadID:              "thread",
		turnID:                "turn",
		windowID:              "window",
		promptCacheMappings:   make(map[string]string),
		promptCacheGenerated:  make(map[string]struct{}),
		conversationMappings:  make(map[string]string),
		conversationGenerated: make(map[string]struct{}),
	}
	body, err := json.Marshal(map[string]any{
		"deviceID":           "raw-device-id",
		"installationID":     "raw-installation-id",
		"sessionID":          "raw-session-id",
		"threadID":           "raw-thread-id",
		"turnID":             "raw-turn-id",
		"windowID":           "raw-window-id",
		"conversationID":     "raw-conversation-id",
		"previousResponseID": "raw-previous-response-id",
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := sanitizeCodexPrivacyRequestBody(body, account, ids, "test-deployment-secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"raw-device-id", "raw-installation-id", "raw-session-id", "raw-thread-id",
		"raw-turn-id", "raw-window-id", "raw-conversation-id", "raw-previous-response-id",
	} {
		if strings.Contains(string(out), raw) {
			t.Errorf("raw uppercase-ID alias %q survived strict sanitizer: %s", raw, out)
		}
	}
}

func TestNormalizeCodexPrivacyKeyResponsesAPIClientMetadataAliases(t *testing.T) {
	for _, key := range []string{
		"ResponsesAPIClientMetadata",
		"responsesApiClientMetadata",
		"responsesapiclientmetadata",
	} {
		if got := normalizeCodexPrivacyKey(key); got != "responsesapi_client_metadata" {
			t.Errorf("normalizeCodexPrivacyKey(%q) = %q, want canonical carrier", key, got)
		}
	}
}

func TestNormalizeCodexPrivacyKeyAcronymIDAliases(t *testing.T) {
	tests := map[string]string{
		"conversationID":                "conversation_id",
		"previousResponseID":            "previous_response_id",
		"sessionID":                     "session_id",
		"threadID":                      "thread_id",
		"turnID":                        "turn_id",
		"windowID":                      "window_id",
		"installationID":                "installation_id",
		"deviceID":                      "device_id",
		"xClientRequestID":              "x_client_request_id",
		"responses_api_client_metadata": "responsesapi_client_metadata",
	}
	for key, want := range tests {
		if got := normalizeCodexPrivacyKey(key); got != want {
			t.Errorf("normalizeCodexPrivacyKey(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestSanitizeCodexPrivacyRequestBodyDropsResponsesAPIClientMetadataAliases(t *testing.T) {
	account := &Account{
		ID:       42,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{codexFingerprintModeExtraKey: string(codexFingerprintSession)},
	}
	ids := &codexFingerprintIDs{
		installationID:        "installation",
		sessionID:             "session",
		threadID:              "thread",
		turnID:                "turn",
		windowID:              "window",
		promptCacheMappings:   make(map[string]string),
		promptCacheGenerated:  make(map[string]struct{}),
		conversationMappings:  make(map[string]string),
		conversationGenerated: make(map[string]struct{}),
	}

	for _, key := range []string{"ResponsesAPIClientMetadata", "responsesApiClientMetadata", "responses_api_client_metadata"} {
		body, err := json.Marshal(map[string]any{
			key:               map[string]any{"cwd": "C:/private", "device_id": "raw-device"},
			"client_metadata": map[string]any{key: map[string]any{"cwd": "nested-private"}},
		})
		if err != nil {
			t.Fatalf("marshal %s: %v", key, err)
		}
		out, err := sanitizeCodexPrivacyRequestBody(body, account, ids, "test-deployment-secret")
		if err != nil {
			t.Fatalf("sanitize %s: %v", key, err)
		}
		var root map[string]any
		if err := json.Unmarshal(out, &root); err != nil {
			t.Fatalf("unmarshal %s: %v", key, err)
		}
		if _, exists := root[key]; exists {
			t.Errorf("root alias %q survived strict sanitizer: %s", key, out)
		}
		metadata, ok := root["client_metadata"].(map[string]any)
		if !ok {
			t.Fatalf("canonical client_metadata missing for %s: %s", key, out)
		}
		if _, exists := metadata[key]; exists {
			t.Errorf("nested alias %q survived strict sanitizer: %s", key, out)
		}
	}
}

func TestCodexFingerprintSeedAndErrorHelpersKeepNonOAuthBehavior(t *testing.T) {
	if ShouldEnsureCodexFingerprintSeedForExtraUpdates(map[string]any{"unrelated": true}) {
		t.Fatal("unrelated Extra updates must not enter the OAuth seed path")
	}
	if !ShouldEnsureCodexFingerprintSeedForExtraUpdates(map[string]any{codexFingerprintModeExtraKey: "session"}) {
		t.Fatal("an explicit OAuth session mode must request a managed seed")
	}
	if ShouldEnsureCodexFingerprintSeedForExtraUpdates(map[string]any{codexFingerprintModeExtraKey: "off"}) {
		t.Fatal("explicit OAuth off mode must not request a managed seed")
	}

	apiKey := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	body := []byte("{\"error\":\"line1\\nline2\"}")
	if got, want := codexPrivacyBodyMarker(apiKey, body, 4096), truncateString(string(body), 4096); got != want {
		t.Fatalf("non-OAuth body marker changed: got %q want %q", got, want)
	}
	message := "  upstream detail  "
	if got := codexPrivacyUpstreamMessage(apiKey, 500, message); got != message {
		t.Fatalf("non-OAuth upstream message changed: got %q want %q", got, message)
	}
}
