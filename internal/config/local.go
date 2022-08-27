package config

import (
	"fmt"

	"github.com/caarlos0/env/v6"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
)

type UserService struct {
	Key     string `env:"USER_SERVICE_KEY"`
	Address string `env:"USER_SERVICE_ADDRESS" envDefault:"https://api.k8deploy.dev/v1/user"`
}
type CompanyService struct {
	Key     string `env:"COMPANY_SERVICE_KEY"`
	Address string `env:"COMPANY_SERVICE_ADDRESS" envDefault:"https://api.k8sdeploy.dev/v1/company"`
}
type HooksService struct {
	Key     string `env:"HOOKS_SERVICE_KEY"`
	Address string `env:"HOOKS_SERVICE_ADDRESS" envDefault:"https://hooks.k8sdeploy.dev/v1/"`
}
type BillingService struct {
	Key     string `env:"BILLING_SERVICE_KEY"`
	Address string `env:"BILLING_SERVICE_ADDRESS" envDefault:"https://api.k8sdeploy.dev/v1/billing"`
}
type PermissionService struct {
	Key     string `env:"PERMISSION_SERVICE_KEY"`
	Address string `env:"PERMISSION_SERVICE_ADDRESS" envDefault:"https://api.k8sdeploy.dev/v1/permission"`
}

type Services struct {
	UserService
	CompanyService
	HooksService
	BillingService
	PermissionService
}

type Local struct {
	KeepLocal   bool `env:"LOCAL_ONLY" envDefault:"false" json:"keep_local,omitempty"`
	Development bool `env:"DEVELOPMENT" envDefault:"false" json:"development,omitempty"`
	HTTPPort    int  `env:"HTTP_PORT" envDefault:"3000" json:"port,omitempty"`
	GRPCPort    int  `env:"GRPC_PORT" envDefault:"8001" json:"grpc_port,omitempty"`

	OnePasswordKey  string `env:"ONE_PASSWORD_KEY" json:"one_password_key,omitempty"`
	OnePasswordPath string `env:"ONE_PASSWORD_PATH" json:"one_password_path,omitempty"`

	Services `json:"services"`
}

func BuildLocal(cfg *Config) error {
	local := &Local{}
	if err := env.Parse(local); err != nil {
		return err
	}
	cfg.Local = *local

	if err := BuildServiceKeys(cfg); err != nil {
		return bugLog.Errorf("failed to build service keys: %s", err.Error())
	}
	if err := BuildServiceKey(cfg); err != nil {
		return bugLog.Errorf("failed to build service key: %s", err.Error())
	}

	return nil
}

func BuildServiceKey(cfg *Config) error {
	if cfg.Local.OnePasswordKey != "" {
		return nil
	}

	onePasswordKeyData, err := cfg.getVaultSecrets(cfg.Local.OnePasswordPath)
	if err != nil {
		return err
	}

	for ik, iv := range onePasswordKeyData {
		if ik == "password" {
			cfg.Local.OnePasswordKey = iv.(string)
		}
	}
	return nil
}

// nolint:gocyclo
func BuildServiceKeys(cfg *Config) error {
	vaultSecrets, err := cfg.getVaultSecrets("kv/data/retro-board/api-keys")
	if err != nil {
		return err
	}

	if vaultSecrets == nil {
		return fmt.Errorf("api keys not found in vault")
	}

	secrets, err := ParseKVSecrets(vaultSecrets)
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		switch secret.Key {
		case "hooks":
			cfg.Local.Services.HooksService.Key = secret.Value
		case "user":
			cfg.Local.Services.UserService.Key = secret.Value
		case "company":
			cfg.Local.Services.CompanyService.Key = secret.Value
		case "billing":
			cfg.Local.Services.BillingService.Key = secret.Value
		case "permission":
			cfg.Local.Services.PermissionService.Key = secret.Value
		}
	}

	return nil
}
