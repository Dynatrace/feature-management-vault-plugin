package featuremanagement

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

func TestMetrics_IssuedAndRevoked(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m, err := newMetrics(provider.Meter(instrumentationName))
	require.NoError(t, err)

	ctx := context.Background()
	coord, err := parseCoordinate("dt01", "production", "checkout", "server")
	require.NoError(t, err)

	m.recordIssued(ctx, coord, true)                                    // minted
	m.recordIssued(ctx, coord, false)                                   // re-leased existing
	m.recordRevoked(ctx, "server", "production", nil)                   // ok
	m.recordRevoked(ctx, "server", "production", fmclient.ErrNotFound)  // ok (already gone)
	m.recordRevoked(ctx, "server", "production", errors.New("FM down")) // error

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))

	require.EqualValues(t, 2, sumOf(t, &rm, "feature_management.sdk_keys.issued"))
	require.EqualValues(t, 3, sumOf(t, &rm, "feature_management.sdk_keys.revoked"))
}

// sumOf returns the total across all data points for the named int64 sum metric.
func sumOf(t *testing.T, rm *metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != name {
				continue
			}
			sum, ok := md.Data.(metricdata.Sum[int64])
			require.True(t, ok, "metric %q is not an int64 sum", name)
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			return total
		}
	}
	t.Fatalf("metric %q not found", name)
	return 0
}
