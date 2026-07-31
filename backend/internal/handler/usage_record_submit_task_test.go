package handler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func newUsageRecordTestPool(t *testing.T) *service.UsageRecordWorkerPool {
	t.Helper()
	pool := service.NewUsageRecordWorkerPoolWithOptions(service.UsageRecordWorkerPoolOptions{
		WorkerCount:           1,
		QueueSize:             8,
		TaskTimeout:           time.Second,
		OverflowPolicy:        "drop",
		OverflowSamplePercent: 0,
		AutoScaleEnabled:      false,
	})
	t.Cleanup(pool.Stop)
	return pool
}

func TestGatewayHandlerSubmitUsageRecordTask_WithPool(t *testing.T) {
	pool := newUsageRecordTestPool(t)
	h := &GatewayHandler{usageRecordWorkerPool: pool}

	done := make(chan struct{})
	h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
		close(done)
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("task not executed")
	}
}

func TestGatewayHandlerSubmitUsageRecordTask_WithoutPoolSyncFallback(t *testing.T) {
	h := &GatewayHandler{}
	var called atomic.Bool

	h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("expected deadline in fallback context")
		}
		called.Store(true)
	})

	require.True(t, called.Load())
}

func TestGatewayHandlerSubmitUsageRecordTask_NilTask(t *testing.T) {
	h := &GatewayHandler{}
	require.NotPanics(t, func() {
		h.submitUsageRecordTask(context.Background(), nil)
	})
}

func TestGatewayHandlerSubmitUsageRecordTask_DroppedTaskSyncFallback(t *testing.T) {
	pool := saturatedUsageRecordTestPool(t)
	h := &GatewayHandler{usageRecordWorkerPool: pool.pool}

	var called atomic.Bool
	h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
		called.Store(true)
	})
	close(pool.release)

	require.True(t, called.Load(), "usage settlement must run synchronously when async submit is dropped")
}

func TestGatewayHandlerSubmitUsageRecordTask_WithoutPool_TaskPanicRecovered(t *testing.T) {
	h := &GatewayHandler{}
	var called atomic.Bool

	require.NotPanics(t, func() {
		h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
			panic("usage task panic")
		})
	})

	h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
		called.Store(true)
	})
	require.True(t, called.Load(), "panic 后后续任务应仍可执行")
}

func TestOpenAIGatewayHandlerSubmitUsageRecordTask_WithPool(t *testing.T) {
	pool := newUsageRecordTestPool(t)
	h := &OpenAIGatewayHandler{usageRecordWorkerPool: pool}

	done := make(chan struct{})
	h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
		close(done)
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("task not executed")
	}
}

func TestOpenAIGatewayHandlerSubmitUsageRecordTask_WithoutPoolSyncFallback(t *testing.T) {
	h := &OpenAIGatewayHandler{}
	var called atomic.Bool

	h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("expected deadline in fallback context")
		}
		called.Store(true)
	})

	require.True(t, called.Load())
}

func TestOpenAIGatewayHandlerSubmitUsageRecordTask_NilTask(t *testing.T) {
	h := &OpenAIGatewayHandler{}
	require.NotPanics(t, func() {
		h.submitUsageRecordTask(context.Background(), nil)
	})
}

func TestOpenAIGatewayHandlerSubmitUsageRecordTask_WithoutPool_TaskPanicRecovered(t *testing.T) {
	h := &OpenAIGatewayHandler{}
	var called atomic.Bool

	require.NotPanics(t, func() {
		h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
			panic("usage task panic")
		})
	})

	h.submitUsageRecordTask(context.Background(), func(ctx context.Context) {
		called.Store(true)
	})
	require.True(t, called.Load(), "panic 后后续任务应仍可执行")
}

func TestOpenAIGatewayHandlerSubmitMandatoryUsageRecordTask_DroppedTaskSyncFallback(t *testing.T) {
	saturated := saturatedUsageRecordTestPool(t)
	h := &OpenAIGatewayHandler{usageRecordWorkerPool: saturated.pool}

	var called atomic.Bool
	h.submitMandatoryUsageRecordTask(context.Background(), func(ctx context.Context) {
		called.Store(true)
	})
	close(saturated.release)

	require.True(t, called.Load(), "mandatory usage task must run synchronously when async submit is dropped")
}

func TestOpenAIGatewayHandlerSubmitOpenAIUsageRecordTask_ImageResultUsesMandatoryFallback(t *testing.T) {
	saturated := saturatedUsageRecordTestPool(t)
	h := &OpenAIGatewayHandler{usageRecordWorkerPool: saturated.pool}

	var called atomic.Bool
	h.submitOpenAIUsageRecordTask(context.Background(), &service.OpenAIForwardResult{ImageCount: 1}, func(ctx context.Context) {
		called.Store(true)
	})
	close(saturated.release)

	require.True(t, called.Load(), "image usage task must be mandatory when async submit is dropped")
}

func TestOpenAIGatewayHandlerSubmitOpenAIUsageRecordTask_TokenResultUsesMandatoryFallback(t *testing.T) {
	saturated := saturatedUsageRecordTestPool(t)
	h := &OpenAIGatewayHandler{usageRecordWorkerPool: saturated.pool}

	var called atomic.Bool
	h.submitOpenAIUsageRecordTask(context.Background(), &service.OpenAIForwardResult{}, func(ctx context.Context) {
		called.Store(true)
	})
	close(saturated.release)

	require.True(t, called.Load(), "token usage task must be mandatory when async submit is dropped")
}

type saturatedUsageRecordPool struct {
	pool    *service.UsageRecordWorkerPool
	release chan struct{}
}

func saturatedUsageRecordTestPool(t *testing.T) saturatedUsageRecordPool {
	t.Helper()
	pool := service.NewUsageRecordWorkerPoolWithOptions(service.UsageRecordWorkerPoolOptions{
		WorkerCount:           1,
		QueueSize:             1,
		TaskTimeout:           time.Second,
		OverflowPolicy:        "drop",
		OverflowSamplePercent: 0,
		AutoScaleEnabled:      false,
	})
	t.Cleanup(pool.Stop)

	block := make(chan struct{})
	release := make(chan struct{})
	pool.Submit(func(ctx context.Context) {
		close(block)
		<-release
	})
	<-block
	pool.Submit(func(ctx context.Context) {})
	return saturatedUsageRecordPool{pool: pool, release: release}
}
