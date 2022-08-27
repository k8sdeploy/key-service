package config

import (
	"errors"

	"github.com/caarlos0/env/v6"
)

type Mongo struct {
	Host     string `env:"MONGO_HOST" envDefault:"localhost"`
	Username string `env:"MONGO_USER" envDefault:""`
	Password string `env:"MONGO_PASS" envDefault:""`
}

func BuildMongo(c *Config) error {
	mongo := &Mongo{}

	if err := env.Parse(mongo); err != nil {
		return err
	}

	creds, err := c.getVaultSecrets("kv/data/k8sdeploy/key-service-mongodb")
	if err != nil {
		return err
	}

	if creds == nil {
		return errors.New("no mongo password found")
	}

	kvs, err := ParseKVSecrets(creds)
	if err != nil {
		return err
	}
	if len(kvs) == 0 {
		return errors.New("no mongo details found")
	}

	kvStrings := KVStrings(kvs)
	mongo.Password = kvStrings["password"]
	mongo.Username = kvStrings["username"]
	mongo.Host = kvStrings["host"]
	c.Mongo = *mongo

	return nil
}
