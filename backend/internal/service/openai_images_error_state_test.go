//go:build unit

package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestOpenAIImagesUpstreamErrorFromGJSONPreservesExplicitStatus(t *testing.T) {
	err := openAIImagesUpstreamErrorFromGJSON(gjson.Parse(`{"type":"server_error","status_code":503,"message":"service unavailable"}`), "req-1")
	require.NotNil(t, err)
	require.Equal(t, http.StatusServiceUnavailable, err.StatusCode)
	require.Equal(t, "req-1", err.UpstreamRequestID)
}

func TestOpenAIStreamFailureStatusRecognizesPlainServiceUnavailable(t *testing.T) {
	status := openAIStreamFailureStatus([]byte(`{"type":"response.failed","error":{"message":"service unavailable"}}`), "")
	require.Equal(t, http.StatusServiceUnavailable, status)
}

// A configured image error passthrough rule must not bypass the account health
// transition. The response shape is independent from whether the upstream
// status is 401/429/503/403; this regression uses OAuth 503 because it should
// install the bounded OAuth quarantine immediately.
func TestOpenAIImagesErrorPassthroughUpdatesAccountState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &rateLimitAccountRepoStub{}
	rateLimit := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	svc := &OpenAIGatewayService{
		cfg:              &config.Config{},
		rateLimitService: rateLimit,
	}
	account := &Account{
		ID:       901,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	bindPassthroughRule(c, PlatformOpenAI, []string{"temporarily unavailable"}, http.StatusTeapot)

	resp := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"service temporarily unavailable"}}`)),
	}

	_, err := svc.handleOpenAIImagesErrorResponse(context.Background(), resp, c, account, "gpt-5.5")

	require.Error(t, err)
	require.Equal(t, http.StatusTeapot, rec.Code, "the passthrough response must remain unchanged")
	require.Equal(t, 1, repo.tempCalls, "image passthrough must persist the OAuth 503 quarantine")
	require.Equal(t, int64(account.ID), repo.lastTempID)
	require.Equal(t, openAIOAuth503TempReason, repo.lastTempReason)
	require.NotNil(t, account.TempUnschedulableUntil)
}
