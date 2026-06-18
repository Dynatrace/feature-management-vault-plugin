// Command vault-plugin-secrets-feature-management is the entrypoint binary for
// the Feature Management Vault secrets-engine plugin.
package main

import (
	"context"
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"

	featuremanagement "github.com/dynatrace/feature-management-vault-plugin"
)

// version is reported as the OTEL service.version; override via
// -ldflags "-X main.version=<v>".
var version = "dev"

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Info,
		Output:     os.Stderr,
		JSONFormat: true,
	})

	// Best-effort: keep secrets out of swap. Not fatal — Vault core already
	// mlocks, and many container runtimes lack CAP_IPC_LOCK.
	if err := mlock.LockMemory(); err != nil {
		logger.Warn("failed to lock memory; secrets may be paged to swap", "error", err)
	}

	ctx := context.Background()
	shutdownMetrics, err := setupMetrics(ctx, logger)
	if err != nil {
		logger.Warn("failed to set up OpenTelemetry metrics; continuing without them", "error", err)
		shutdownMetrics = func(context.Context) error { return nil }
	}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logger.Error("failed to parse plugin flags", "error", err)
		_ = shutdownMetrics(ctx)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	serveErr := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: featuremanagement.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             logger,
	})

	// Flush any buffered metrics before exit.
	_ = shutdownMetrics(context.Background())
	if serveErr != nil {
		logger.Error("plugin shutting down", "error", serveErr)
		os.Exit(1)
	}
}

// setupMetrics wires an OTLP metrics exporter when an OTLP endpoint is configured
// (OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_METRICS_ENDPOINT). Otherwise
// the global meter provider stays a no-op and the plugin records nothing — so an
// unconfigured deployment never attempts to connect. All exporter knobs (endpoint,
// headers, TLS, interval) come from the standard OTEL_* environment variables.
func setupMetrics(ctx context.Context, logger hclog.Logger) (func(context.Context) error, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") == "" {
		logger.Info("OpenTelemetry metrics disabled (set OTEL_EXPORTER_OTLP_ENDPOINT to enable)")
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlpmetricgrpc.New(ctx)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName("vault-plugin-secrets-feature-management"),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		res = resource.Default()
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
	)
	otel.SetMeterProvider(provider)
	logger.Info("OpenTelemetry metrics enabled (OTLP exporter)")
	return provider.Shutdown, nil
}
