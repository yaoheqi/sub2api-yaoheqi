//go:build unit

package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProjectAccountAvailabilityAt(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Minute)
	past := now.Add(-time.Minute)

	tests := []struct {
		name    string
		account *Account
		want    AccountAvailabilityReason
		ready   bool
	}{
		{name: "missing", want: AccountAvailabilityMissing},
		{name: "inactive", account: &Account{Status: StatusError, Schedulable: true}, want: AccountAvailabilityInactive},
		{name: "manual pause", account: &Account{Status: StatusActive}, want: AccountAvailabilityManualPause},
		{name: "expired", account: &Account{Status: StatusActive, Schedulable: true, AutoPauseOnExpired: true, ExpiresAt: &past}, want: AccountAvailabilityExpired},
		{name: "overloaded", account: &Account{Status: StatusActive, Schedulable: true, OverloadUntil: &future}, want: AccountAvailabilityOverloaded},
		{name: "rate limited", account: &Account{Status: StatusActive, Schedulable: true, RateLimitResetAt: &future}, want: AccountAvailabilityRateLimited},
		{name: "temporary block", account: &Account{Status: StatusActive, Schedulable: true, TempUnschedulableUntil: &future}, want: AccountAvailabilityTemporaryBlock},
		{name: "elapsed windows are ready", account: &Account{Status: StatusActive, Schedulable: true, OverloadUntil: &past, RateLimitResetAt: &past, TempUnschedulableUntil: &past}, want: AccountAvailabilityReady, ready: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProjectAccountAvailabilityAt(tt.account, now)
			require.Equal(t, tt.want, got.Reason)
			require.Equal(t, tt.ready, got.Schedulable)
		})
	}
}

func TestProjectShadowCredentialAvailabilityAtDoesNotPropagateManualPause(t *testing.T) {
	now := time.Now()
	account := &Account{Status: StatusActive, Schedulable: false, OverloadUntil: availabilityTimePtr(now.Add(time.Minute)), RateLimitResetAt: availabilityTimePtr(now.Add(time.Minute))}
	availability := ProjectShadowCredentialAvailabilityAt(account, now)
	require.True(t, availability.Schedulable)
	require.Equal(t, AccountAvailabilityReady, availability.Reason)

	account.TempUnschedulableUntil = availabilityTimePtr(now.Add(time.Minute))
	availability = ProjectShadowCredentialAvailabilityAt(account, now)
	require.False(t, availability.Schedulable)
	require.Equal(t, AccountAvailabilityTemporaryBlock, availability.Reason)
}

func TestProjectAccountSchedulingStateKeepsAllActiveSources(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Minute)
	account := &Account{
		Status: StatusActive, Schedulable: false,
		RateLimitResetAt:        &future,
		TempUnschedulableUntil:  &future,
		TempUnschedulableReason: `{"source":"manual_test"}`,
	}
	state := ProjectAccountSchedulingStateAt(account, now, []AccountSchedulingBlock{{Source: "runtime:429", Until: &future}})
	require.False(t, state.Schedulable)
	require.Len(t, state.Blocks, 4)
	require.Equal(t, "schedulable", state.Blocks[0].Source)
	require.Equal(t, "runtime:429", state.Blocks[3].Source)
}

func TestProjectAccountSchedulingStateDropsExpiredRuntimeBlock(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Second)
	state := ProjectAccountSchedulingStateAt(&Account{Status: StatusActive, Schedulable: true}, now,
		[]AccountSchedulingBlock{{Source: "runtime", Until: &expired}})
	require.True(t, state.Schedulable)
	require.Empty(t, state.Blocks)
}

func availabilityTimePtr(value time.Time) *time.Time {
	return &value
}
