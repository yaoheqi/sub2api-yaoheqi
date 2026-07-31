package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestGetAllGroupUsageSummaryCachesFullTableAggregation(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := newUsageLogRepositoryWithSQL(nil, db)
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	repo.now = func() time.Time { return now }
	todayStart := now.Truncate(24 * time.Hour)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT")).
		WithArgs(todayStart).
		WillReturnRows(sqlmock.NewRows([]string{"group_id", "total_cost", "today_cost"}).AddRow(7, 12.5, 2.5))

	first, err := repo.GetAllGroupUsageSummary(context.Background(), todayStart)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, 12.5, first[0].TotalCost)

	first[0].TotalCost = 999
	second, err := repo.GetAllGroupUsageSummary(context.Background(), todayStart)
	require.NoError(t, err)
	require.Equal(t, 12.5, second[0].TotalCost, "callers must not mutate the cached value")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetAllGroupUsageSummaryRefreshesAfterTTL(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := newUsageLogRepositoryWithSQL(nil, db)
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	repo.now = func() time.Time { return now }
	todayStart := now.Truncate(24 * time.Hour)

	for _, total := range []float64{10, 11} {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT")).
			WithArgs(todayStart).
			WillReturnRows(sqlmock.NewRows([]string{"group_id", "total_cost", "today_cost"}).AddRow(7, total, 2.5))
	}

	first, err := repo.GetAllGroupUsageSummary(context.Background(), todayStart)
	require.NoError(t, err)
	require.Equal(t, 10.0, first[0].TotalCost)

	now = now.Add(groupUsageSummaryCacheTTL)
	second, err := repo.GetAllGroupUsageSummary(context.Background(), todayStart)
	require.NoError(t, err)
	require.Equal(t, 11.0, second[0].TotalCost)
	require.NoError(t, mock.ExpectationsWereMet())
}
