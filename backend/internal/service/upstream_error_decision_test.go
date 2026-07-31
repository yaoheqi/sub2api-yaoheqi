//go:build unit

package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyOpenAI403(t *testing.T) {
	account := &Account{ID: 1, Platform: PlatformOpenAI}
	tests := []struct {
		name       string
		body       string
		class      string
		scope      UpstreamErrorScope
		retry      UpstreamRetryMode
		transition AccountTransitionAction
	}{
		{
			name:       "html edge rejection retries immediately",
			body:       `<html><head></head><body>forbidden</body></html>`,
			class:      "transient_html_forbidden",
			scope:      UpstreamErrorScopeProvider,
			retry:      UpstreamRetryImmediate,
			transition: AccountTransitionNone,
		},
		{
			name:       "unknown forbidden retries without account mutation",
			body:       `{"error":{"message":"temporary edge rejection"}}`,
			class:      "transient_forbidden",
			scope:      UpstreamErrorScopeProvider,
			retry:      UpstreamRetryImmediate,
			transition: AccountTransitionNone,
		},
		{
			name:       "image permission fails over without account mutation",
			body:       `{"error":{"message":"Image generation is not enabled for this group"}}`,
			class:      "feature_not_enabled",
			scope:      UpstreamErrorScopeRequest,
			retry:      UpstreamRetryFailover,
			transition: AccountTransitionNone,
		},
		{
			name:       "billing forbidden changes account availability",
			body:       `{"error":{"message":"insufficient balance"}}`,
			class:      "billing_forbidden",
			scope:      UpstreamErrorScopeAccount,
			retry:      UpstreamRetryFailover,
			transition: AccountTransitionCooldown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, matched := classifyOpenAI403(account, http.StatusForbidden, "", []byte(tt.body))
			require.True(t, matched)
			require.Equal(t, tt.class, decision.Class)
			require.Equal(t, tt.scope, decision.Scope)
			require.Equal(t, tt.retry, decision.Retry)
			require.Equal(t, tt.transition, decision.Transition)
			require.True(t, decision.Failover)
		})
	}
}

func TestClassifyOpenAI403IgnoresOtherPlatformsAndStatuses(t *testing.T) {
	_, matched := classifyOpenAI403(&Account{Platform: PlatformAnthropic}, http.StatusForbidden, "", nil)
	require.False(t, matched)
	_, matched = classifyOpenAI403(&Account{Platform: PlatformOpenAI}, http.StatusUnauthorized, "", nil)
	require.False(t, matched)
}
