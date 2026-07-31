package service

import "time"

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
	if account == nil {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityMissing, Source: "account"}
	}
	if !account.IsActive() {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityInactive, Source: "status"}
	}
	if !account.Schedulable {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityManualPause, Source: "schedulable"}
	}
	if account.AutoPauseOnExpired && account.ExpiresAt != nil && !now.Before(*account.ExpiresAt) {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityExpired, Source: "expires_at", Until: account.ExpiresAt}
	}
	if account.OverloadUntil != nil && now.Before(*account.OverloadUntil) {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityOverloaded, Source: "overload_until", Until: account.OverloadUntil}
	}
	if account.RateLimitResetAt != nil && now.Before(*account.RateLimitResetAt) {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityRateLimited, Source: "rate_limit_reset_at", Until: account.RateLimitResetAt}
	}
	if account.TempUnschedulableUntil != nil && now.Before(*account.TempUnschedulableUntil) {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityTemporaryBlock, Source: "temp_unschedulable_until", Until: account.TempUnschedulableUntil}
	}
	if account.IsAPIKeyOrBedrock() && account.IsQuotaExceeded() {
		return AccountSchedulingAvailability{Reason: AccountAvailabilityQuotaExceeded, Source: "quota"}
	}
	return AccountSchedulingAvailability{Schedulable: true, Reason: AccountAvailabilityReady, Source: "projection"}
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
