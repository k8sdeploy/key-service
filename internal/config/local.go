package config

import (
	"fmt"

	"github.com/caarlos0/env/v6"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
)

type UserService struct {
	Key     string `env:"USER_SERVICE_KEY"`
	Address string `env:"USER_SERVICE_ADDRESS" envDefault:"https://user-service.k8sdeploy"`
}
type CompanyService struct {
	Key     string `env:"COMPANY_SERVICE_KEY"`
	Address string `env:"COMPANY_SERVICE_ADDRESS" envDefault:"https://company-service.k8sdeploy"`
}
type HooksService struct {
	Key     string `env:"HOOKS_SERVICE_KEY"`
	Address string `env:"HOOKS_SERVICE_ADDRESS" envDefault:"https://hooks-service.k8sdeploy"`
}
type BillingService struct {
	Key     string `env:"BILLING_SERVICE_KEY"`
	Address string `env:"BILLING_SERVICE_ADDRESS" envDefault:"https://billing-service.k8sdeploy"`
}
type PermissionService struct {
	Key     string `env:"PERMISSION_SERVICE_KEY"`
	Address string `env:"PERMISSION_SERVICE_ADDRESS" envDefault:"https://permissions-service.k8sdeploy"`
}
type Orchestrator struct {
	Key     string `env:"ORCHESTRATOR_KEY"`
	Address string `env:"ORCHESTRATOR_ADDRESS" envDefault:"https://orchestrator.k8sdeploy"`
}

type Services struct {
	UserService
	CompanyService
	HooksService
	BillingService
	PermissionService
	Orchestrator
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

	return nil
}

// nolint:gocyclo
func BuildServiceKeys(cfg *Config) error {
	vaultSecrets, err := cfg.getVaultSecrets("kv/data/k8sdeploy/api-keys")
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
		case "orchestrator":
			cfg.Local.Services.Orchestrator.Key = secret.Value
		}
	}

	return nil
}
