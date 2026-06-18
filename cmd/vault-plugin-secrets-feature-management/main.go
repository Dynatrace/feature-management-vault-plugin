// Command vault-plugin-secrets-feature-management is the entrypoint binary for
// the Feature Management Vault secrets-engine plugin.
package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	featuremanagement "github.com/dynatrace/feature-management-vault-plugin"
)

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

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logger.Error("failed to parse plugin flags", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: featuremanagement.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             logger,
	}); err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
