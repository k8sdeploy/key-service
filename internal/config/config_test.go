package config_test

import (
	"os"
	"testing"

	"github.com/caarlos0/env/v6"
	"github.com/k8sdeploy/key-service/internal/config"
)

func TestServiceKey(t *testing.T) {
	if os.Getenv("VAULT_ADDRESS") == "" {
		t.Skip("VAULT_ADDRESS not set")
	}
	if os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("VAULT_TOKEN not set")
	}
	if os.Getenv("ONE_PASSWORD_KEY") == "" {
		t.Skip("ONE_PASSWORD_KEY not set")
	}

	cfg := &config.Config{}

	if err := env.Parse(cfg); err != nil {
		t.Errorf("parse env: %v", err)
	}

	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "defined service key",
			cfg: &config.Config{
				Local: config.Local{
					OnePasswordKey: "tester",
				},
			},
			want: "tester",
		},
		{
			name: "env service key",
			cfg: &config.Config{
				Local: config.Local{
					OnePasswordKey: os.Getenv("ONE_PASSWORD_KEY"),
				},
			},
			want: os.Getenv("ONE_PASSWORD_KEY"),
		},
		{
			name: "retrieve service key",
			cfg: &config.Config{
				Local: config.Local{
					OnePasswordPath: os.Getenv("ONE_PASSWORD_PATH"),
				},
				Vault: config.Vault{
					Address: os.Getenv("VAULT_ADDRESS"),
					Token:   os.Getenv("VAULT_TOKEN"),
				},
			},
			want: os.Getenv("ONE_PASSWORD_KEY"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := config.BuildServiceKeys(tt.cfg); err != nil {
				t.Errorf("BuildServiceKey: %v", err)
			}
			if tt.cfg.Local.OnePasswordKey != tt.want {
				t.Errorf("got: %v, want: %v", tt.cfg.Local.OnePasswordKey, tt.want)
			}
		})
	}
}
