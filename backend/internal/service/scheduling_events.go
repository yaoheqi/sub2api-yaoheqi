package service

import (
	"log/slog"
)

// logSchedulingEvent is the common low-cardinality event shape for scheduler
// decisions. Detailed request data remains in the existing debug logs.
func logSchedulingEvent(event string, accountID int64, attrs ...any) {
	args := []any{"event", event}
	if accountID > 0 {
		args = append(args, "account_id", accountID)
	}
	args = append(args, attrs...)
	slog.Info("scheduler_event", args...)
}
