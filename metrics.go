package featuremanagement

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
)

// instrumentationName is the OpenTelemetry instrumentation scope for this plugin.
const instrumentationName = "github.com/dynatrace/feature-management-vault-plugin"

// metrics holds the OpenTelemetry instruments for the SDK-key lifecycle.
type metrics struct {
	issued metric.Int64Counter
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
	return &metrics{issued: issued}, nil
}

// newDefaultMetrics builds instruments from the global OTEL meter provider, a no-op when unset.
func newDefaultMetrics() *metrics {
	m, err := newMetrics(otel.Meter(instrumentationName))
	if err != nil {
		// unreachable in practice; fall back to no-ops so callers can't panic
		m, _ = newMetrics(metricnoop.NewMeterProvider().Meter(instrumentationName))
	}
	return m
}

// recordIssued counts an SDK key handed to a consumer; provisioned is true when FM was consulted.
func (m *metrics) recordIssued(ctx context.Context, coord coordinate, provisioned bool) {
	m.issued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", string(coord.Type)),
		attribute.String("release_stage", coord.ReleaseStage),
		attribute.Bool("provisioned", provisioned),
	))
}
