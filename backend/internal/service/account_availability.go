package service

import "time"

// AccountSchedulingBlock describes one independent reason why an account is
// currently excluded from scheduling. Keeping the source and expiry together
// prevents callers from inferring state from unrelated nullable columns.
type AccountSchedulingBlock struct {
	Source string     `json:"source"`
	Reason string     `json:"reason,omitempty"`
	Until  *time.Time `json:"until,omitempty"`
}

// AccountSchedulingState is the canonical scheduling projection. Blocks are
// additive: an account is schedulable only when no active block remains.
type AccountSchedulingState struct {
	Schedulable bool                      `json:"schedulable"`
	Reason      AccountAvailabilityReason `json:"reason"`
	Blocks      []AccountSchedulingBlock  `json:"blocks,omitempty"`
}

// AccountRuntimeBlockReader exposes process-local circuit breakers to the
// canonical projection without coupling the projection to a gateway service.
type AccountRuntimeBlockReader interface {
	SchedulingBlocks(accountID int64, now time.Time) []AccountSchedulingBlock
}

type AccountAvailabilityReason string

const (
	AccountAvailabilityReady          AccountAvailabilityReason = "ready"
	AccountAvailabilityMissing        AccountAvailabilityReason = "missing"
	AccountAvailabilityInactive       AccountAvailabilityReason = "inactive"
	AccountAvailabilityManualPause    AccountAvailabilityReason = "manual_pause"
	AccountAvailabilityExpired        AccountAvailabilityReason = "expired"
	AccountAvailabilityOverloaded     AccountAvailabilityReason = "overloaded"
	AccountAvailabilityRateLimited    AccountAvailabilityReason = "rate_limited"
	AccountAvailabilityTemporaryBlock AccountAvailabilityReason = "temporary_block"
	AccountAvailabilityQuotaExceeded  AccountAvailabilityReason = "quota_exceeded"
)

type AccountSchedulingAvailability struct {
	Schedulable bool
	Reason      AccountAvailabilityReason
	Source      string
	Until       *time.Time
}

// ProjectAccountAvailabilityAt is the canonical projection from persisted
// account fields to scheduler availability. It intentionally preserves the
// existing precedence so callers can migrate without changing behavior.
func ProjectAccountAvailabilityAt(account *Account, now time.Time) AccountSchedulingAvailability {
	state := ProjectAccountSchedulingStateAt(account, now, nil)
	if state.Schedulable {
		return AccountSchedulingAvailability{Schedulable: true, Reason: AccountAvailabilityReady, Source: "projection"}
	}
	if len(state.Blocks) == 0 {
		return AccountSchedulingAvailability{Reason: state.Reason, Source: "projection"}
	}
	block := state.Blocks[0]
	return AccountSchedulingAvailability{Reason: state.Reason, Source: block.Source, Until: block.Until}
}

// ProjectAccountSchedulingStateAt returns the single canonical state used by
// scheduler-facing code. runtimeBlocks may contain in-memory blocks from a
// request-path circuit breaker; persisted account fields remain the durable
// source and are projected alongside them.
func ProjectAccountSchedulingStateAt(account *Account, now time.Time, runtimeBlocks []AccountSchedulingBlock) AccountSchedulingState {
	if account == nil {
		return AccountSchedulingState{Reason: AccountAvailabilityMissing}
	}
	blocks := make([]AccountSchedulingBlock, 0, 6+len(runtimeBlocks))
	if !account.IsActive() {
		blocks = append(blocks, AccountSchedulingBlock{Source: "status", Reason: string(AccountAvailabilityInactive)})
	}
	if !account.Schedulable {
		blocks = append(blocks, AccountSchedulingBlock{Source: "schedulable", Reason: string(AccountAvailabilityManualPause)})
	}
	if account.AutoPauseOnExpired && account.ExpiresAt != nil && !now.Before(*account.ExpiresAt) {
		blocks = append(blocks, AccountSchedulingBlock{Source: "expires_at", Reason: string(AccountAvailabilityExpired), Until: account.ExpiresAt})
	}
	if account.OverloadUntil != nil && now.Before(*account.OverloadUntil) {
		blocks = append(blocks, AccountSchedulingBlock{Source: "overload_until", Reason: string(AccountAvailabilityOverloaded), Until: account.OverloadUntil})
	}
	if account.RateLimitResetAt != nil && now.Before(*account.RateLimitResetAt) {
		blocks = append(blocks, AccountSchedulingBlock{Source: "rate_limit_reset_at", Reason: string(AccountAvailabilityRateLimited), Until: account.RateLimitResetAt})
	}
	if account.TempUnschedulableUntil != nil && now.Before(*account.TempUnschedulableUntil) {
		blocks = append(blocks, AccountSchedulingBlock{Source: "temp_unschedulable_until", Reason: account.TempUnschedulableReason, Until: account.TempUnschedulableUntil})
	}
	if account.IsAPIKeyOrBedrock() && account.IsQuotaExceeded() {
		blocks = append(blocks, AccountSchedulingBlock{Source: "quota", Reason: string(AccountAvailabilityQuotaExceeded)})
	}
	for _, block := range runtimeBlocks {
		if block.Until == nil || now.Before(*block.Until) {
			blocks = append(blocks, block)
		}
	}
	if len(blocks) == 0 {
		return AccountSchedulingState{Schedulable: true, Reason: AccountAvailabilityReady}
	}
	reason := AccountAvailabilityTemporaryBlock
	if blocks[0].Reason != "" {
		candidate := AccountAvailabilityReason(blocks[0].Reason)
		switch candidate {
		case AccountAvailabilityInactive, AccountAvailabilityManualPause,
			AccountAvailabilityExpired, AccountAvailabilityOverloaded,
			AccountAvailabilityRateLimited, AccountAvailabilityQuotaExceeded:
			reason = candidate
		}
	}
	return AccountSchedulingState{Reason: reason, Blocks: blocks}
}

// ProjectShadowCredentialAvailabilityAt projects only credential and transport
// health. Manual scheduling, global rate limits, overload, and account quota do
// not propagate from a parent account to its independently metered shadow.
func ProjectShadowCredentialAvailabilityAt(account *Account, now time.Time) AccountSchedulingAvailability {
	if account == nil {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityMissing, Source: "account"}
	}
	if !account.IsActive() {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityInactive, Source: "status"}
	}
	if account.AutoPauseOnExpired && account.ExpiresAt != nil && !now.Before(*account.ExpiresAt) {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityExpired, Source: "expires_at", Until: account.ExpiresAt}
	}
	if account.TempUnschedulableUntil != nil && now.Before(*account.TempUnschedulableUntil) {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityTemporaryBlock, Source: "temp_unschedulable_until", Until: account.TempUnschedulableUntil}
	}
	return AccountSchedulingAvailability{Schedulable: true, Reason: AccountAvailabilityReady, Source: "shadow_credential_projection"}
}
