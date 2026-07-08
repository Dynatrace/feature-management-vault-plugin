package featuremanagement

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// instrumentationName is the OpenTelemetry instrumentation scope for this plugin.
const instrumentationName = "github.com/dynatrace/feature-management-vault-plugin"

// metrics holds the OpenTelemetry instruments for the SDK-key lifecycle. The
// counters are cumulative; "issuance/revocation over time" is the rate a metrics
// backend derives from them.
type metrics struct {
	issued  metric.Int64Counter
	revoked metric.Int64Counter
}

func newMetrics(meter metric.Meter) (*metrics, error) {
	issued, err := meter.Int64Counter(
		"feature_management.sdk_keys.issued",
		metric.WithDescription("SDK keys issued to consumers under a Vault lease."),
		metric.WithUnit("{key}"),
	)
	if err != nil {
		return nil, err
	}
	revoked, err := meter.Int64Counter(
		"feature_management.sdk_keys.revoked",
		metric.WithDescription("SDK key leases revoked."),
		metric.WithUnit("{key}"),
	)
	if err != nil {
		return nil, err
	}
	return &metrics{issued: issued, revoked: revoked}, nil
}

// newDefaultMetrics builds instruments from the global OTEL meter provider. When
// no provider is configured the global one is a no-op, so the instruments — and
// every recordX call — are cheap no-ops.
func newDefaultMetrics() *metrics {
	m, err := newMetrics(otel.Meter(instrumentationName))
	if err != nil {
		// Instrument names/units are constant and valid, so this is effectively
		// unreachable; fall back to explicit no-ops to keep callers panic-free.
		m, _ = newMetrics(metricnoop.NewMeterProvider().Meter(instrumentationName))
	}
	return m
}

// recordIssued counts an SDK key handed to a consumer. minted is true when this
// read created a new key in the FM service (vs. re-leasing the existing one).
func (m *metrics) recordIssued(ctx context.Context, coord coordinate, minted bool) {
	m.issued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", string(coord.Type)),
		attribute.String("release_stage", coord.ReleaseStage),
		attribute.Bool("minted", minted),
	))
}

// recordRevoked counts an SDK key lease revocation. result="error" flags that
// the backing key could not be deleted in the FM service (the orphaned-key risk).
func (m *metrics) recordRevoked(ctx context.Context, keyType, releaseStage string, fmErr error) {
	result := "ok"
	if fmErr != nil && !fmclient.IsNotFound(fmErr) {
		result = "error"
	}
	m.revoked.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", keyType),
		attribute.String("release_stage", releaseStage),
		attribute.String("result", result),
	))
}
