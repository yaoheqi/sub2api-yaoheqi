package service

import (
	"net/http"
	"strings"
)

type UpstreamErrorScope string

const (
	UpstreamErrorScopeRequest  UpstreamErrorScope = "request"
	UpstreamErrorScopeAccount  UpstreamErrorScope = "account"
	UpstreamErrorScopeProvider UpstreamErrorScope = "provider"
)

type UpstreamRetryMode string

const (
	UpstreamRetryNone      UpstreamRetryMode = "none"
	UpstreamRetryImmediate UpstreamRetryMode = "immediate"
	UpstreamRetryFailover  UpstreamRetryMode = "failover"
)

type AccountTransitionAction string

const (
	AccountTransitionNone     AccountTransitionAction = "none"
	AccountTransitionCooldown AccountTransitionAction = "cooldown"
)

type UpstreamRecoveryPolicy string

const (
	UpstreamRecoveryNone    UpstreamRecoveryPolicy = "none"
	UpstreamRecoveryOnTimer UpstreamRecoveryPolicy = "timer"
)

// UpstreamErrorDecision is the protocol-independent result consumed by retry
// and account-state code. It keeps request/provider failures from mutating an
// account merely because they share the same HTTP status.
type UpstreamErrorDecision struct {
	Class      string
	Scope      UpstreamErrorScope
	Retry      UpstreamRetryMode
	Failover   bool
	Transition AccountTransitionAction
	Recovery   UpstreamRecoveryPolicy
}

func classifyOpenAI403(account *Account, statusCode int, upstreamMsg string, responseBody []byte) (UpstreamErrorDecision, bool) {
	if account == nil || account.Platform != PlatformOpenAI || statusCode != http.StatusForbidden {
		return UpstreamErrorDecision{}, false
	}

	text := strings.ToLower(strings.TrimSpace(upstreamMsg + "\n" + string(responseBody)))
	if isHTMLResponseText(text) {
		return UpstreamErrorDecision{
			Class:      "transient_html_forbidden",
			Scope:      UpstreamErrorScopeProvider,
			Retry:      UpstreamRetryImmediate,
			Failover:   true,
			Transition: AccountTransitionNone,
			Recovery:   UpstreamRecoveryNone,
		}, true
	}
	if strings.Contains(text, strings.ToLower(imageGenerationPermissionMessage)) {
		return UpstreamErrorDecision{
			Class:      "feature_not_enabled",
			Scope:      UpstreamErrorScopeRequest,
			Retry:      UpstreamRetryFailover,
			Failover:   true,
			Transition: AccountTransitionNone,
			Recovery:   UpstreamRecoveryNone,
		}, true
	}
	if containsOpenAI403BillingMarker(text) {
		return UpstreamErrorDecision{
			Class:      "billing_forbidden",
			Scope:      UpstreamErrorScopeAccount,
			Retry:      UpstreamRetryFailover,
			Failover:   true,
			Transition: AccountTransitionCooldown,
			Recovery:   UpstreamRecoveryOnTimer,
		}, true
	}

	return UpstreamErrorDecision{
		Class:      "transient_forbidden",
		Scope:      UpstreamErrorScopeProvider,
		Retry:      UpstreamRetryImmediate,
		Failover:   true,
		Transition: AccountTransitionNone,
		Recovery:   UpstreamRecoveryNone,
	}, true
}

func isHTMLResponseText(text string) bool {
	text = strings.TrimSpace(strings.ToLower(text))
	return strings.HasPrefix(text, "<!doctype html") ||
		strings.HasPrefix(text, "<html") ||
		(strings.Contains(text, "<head") && strings.Contains(text, "<body"))
}

func containsOpenAI403BillingMarker(text string) bool {
	text = strings.ToLower(text)
	for _, marker := range openAI403BillingMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
