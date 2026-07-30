//go:build unit

package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type runtimeBlockRecorder struct {
	accounts   []*Account
	until      []time.Time
	reasons    []string
	clearedIDs []int64
}

func (r *runtimeBlockRecorder) BlockAccountScheduling(account *Account, until time.Time, reason string) {
	r.accounts = append(r.accounts, account)
	r.until = append(r.until, until)
	r.reasons = append(r.reasons, reason)
}

func (r *runtimeBlockRecorder) ClearAccountSchedulingBlock(accountID int64) {
	r.clearedIDs = append(r.clearedIDs, accountID)
}

func TestRateLimitService_HandleUpstreamError_OpenAI403NonBillingDoesNotChangeAccountState(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	counter := &openAI403CounterCacheStub{counts: []int64{1}}
	blocker := &runtimeBlockRecorder{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	service.SetOpenAI403CounterCache(counter)
	service.SetAccountRuntimeBlocker(blocker)
	account := &Account{
		ID:       301,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(`{"error":{"message":"temporary edge rejection"}}`),
	)

	require.False(t, shouldDisable)
	require.Zero(t, counter.incrementCalls)
	require.Equal(t, 0, repo.setErrorCalls)
	require.Equal(t, 0, repo.tempCalls)
	require.Empty(t, blocker.accounts)
}

func TestRateLimitService_HandleUpstreamError_OpenAI403HTMLDoesNotChangeAccountState(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	counter := &openAI403CounterCacheStub{counts: []int64{1}}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	service.SetOpenAI403CounterCache(counter)
	account := &Account{ID: 304, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	body := []byte(`<html><head><meta name="viewport" content="width=device-width"></head><body>Access forbidden</body></html>`)

	shouldDisable := service.HandleUpstreamError(context.Background(), account, http.StatusForbidden, http.Header{}, body)

	require.False(t, shouldDisable)
	require.True(t, isOpenAITransientHTML403(account, http.StatusForbidden, body))
	require.Zero(t, counter.incrementCalls)
	require.Zero(t, repo.setErrorCalls)
	require.Zero(t, repo.tempCalls)
}

func TestRateLimitService_HandleUpstreamError_OpenAI403BillingFirstHitTempUnschedulable(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	counter := &openAI403CounterCacheStub{counts: []int64{1}}
	blocker := &runtimeBlockRecorder{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	service.SetOpenAI403CounterCache(counter)
	service.SetAccountRuntimeBlocker(blocker)
	account := &Account{ID: 305, Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	shouldDisable := service.HandleUpstreamError(
		context.Background(), account, http.StatusForbidden, http.Header{},
		[]byte(`{"error":{"message":"insufficient balance for this request"}}`),
	)

	require.True(t, shouldDisable)
	require.Equal(t, 1, counter.incrementCalls)
	require.Equal(t, 1, repo.tempCalls)
	require.Contains(t, repo.lastTempReason, "insufficient balance")
	require.Contains(t, repo.lastTempReason, "(1/3)")
	require.Len(t, blocker.accounts, 1)
}

func TestRateLimitService_HandleUpstreamError_OpenAI403ImageGroupPermissionDoesNotChangeAccountState(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	counter := &openAI403CounterCacheStub{counts: []int64{1}}
	blocker := &runtimeBlockRecorder{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	service.SetOpenAI403CounterCache(counter)
	service.SetAccountRuntimeBlocker(blocker)
	account := &Account{
		ID:       303,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(`{"error":{"message":"Image generation is not enabled for this group"}}`),
	)

	require.False(t, shouldDisable)
	require.Zero(t, counter.incrementCalls)
	require.Zero(t, repo.setErrorCalls)
	require.Zero(t, repo.tempCalls)
	require.Empty(t, blocker.accounts)
}

func TestRateLimitService_HandleUpstreamError_OpenAI403ThresholdDisables(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	counter := &openAI403CounterCacheStub{counts: []int64{3}}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	service.SetOpenAI403CounterCache(counter)
	account := &Account{
		ID:       302,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(`{"error":{"message":"insufficient balance for this request"}}`),
	)

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Equal(t, 0, repo.tempCalls)
	require.Contains(t, repo.lastErrorMsg, "insufficient balance")
	require.Contains(t, repo.lastErrorMsg, "consecutive_403=3/3")
}

func TestRateLimitService_RecoverOpenAI403StateAfterSuccessClearsOnlyNonBillingCooldown(t *testing.T) {
	t.Run("html cooldown", func(t *testing.T) {
		repo := &rateLimitAccountRepoStub{}
		counter := &openAI403CounterCacheStub{}
		blocker := &runtimeBlockRecorder{}
		service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		service.SetOpenAI403CounterCache(counter)
		service.SetAccountRuntimeBlocker(blocker)
		account := &Account{
			ID:                      306,
			Platform:                PlatformOpenAI,
			TempUnschedulableReason: "OpenAI 403 temporary cooldown (1/3): Access forbidden (403): <html>",
		}

		service.RecoverOpenAI403StateAfterSuccess(context.Background(), account)

		require.Equal(t, []int64{account.ID}, counter.resetCalls)
		require.Equal(t, 1, repo.clearTempCalls)
		require.Equal(t, []int64{account.ID}, blocker.clearedIDs)
	})

	t.Run("billing cooldown", func(t *testing.T) {
		repo := &rateLimitAccountRepoStub{}
		counter := &openAI403CounterCacheStub{}
		service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		service.SetOpenAI403CounterCache(counter)
		account := &Account{
			ID:                      307,
			Platform:                PlatformOpenAI,
			TempUnschedulableReason: "OpenAI 403 temporary cooldown (1/3): insufficient balance",
		}

		service.RecoverOpenAI403StateAfterSuccess(context.Background(), account)

		require.Equal(t, []int64{account.ID}, counter.resetCalls)
		require.Zero(t, repo.clearTempCalls)
	})
}
