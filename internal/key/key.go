package key

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/k8sdeploy/key-service/internal/config"
)

type Key struct {
	Config *config.Config
}

type ServiceKey struct {
	Key string
}

type UserKey struct {
	ID      string
	Created time.Time

	Key    string
	Secret string
}

type K8sKey struct {
	ID     string
	Key    string
	Secret string
}

func NewKey(config *config.Config) *Key {
	return &Key{
		Config: config,
	}
}

func (k *Key) GenerateServiceKey(n int) (string, error) {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterRunes))))
		if err != nil {
			return "", err
		}

		b[i] = letterRunes[j.Int64()]
	}
	return string(b), nil
}

func (k *Key) GenerateKey(n int) (string, error) {
	return k.GenerateServiceKey(n)
}

func (k *Key) GetKeys(n int) (*ResponseItem, error) {
	userKey, err := k.GenerateServiceKey(n)
	if err != nil {
		return nil, err
	}
	hooksKey, err := k.GenerateServiceKey(n)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	companyKey, err := k.GenerateServiceKey(n)
	if err != nil {
		return nil, err
	}
	billingKey, err := k.GenerateServiceKey(n)
	if err != nil {
		return nil, err
	}
	permissionKey, err := k.GenerateServiceKey(n)
	if err != nil {
		return nil, err
	}

	return &ResponseItem{
		Status:      "ok",
		User:        userKey,
		Hooks:       hooksKey,
		Company:     companyKey,
		Billing:     billingKey,
		Permissions: permissionKey,
	}, nil
}

func (k *Key) ValidateServiceKey(key string) bool {
	return k.Config.Local.OnePasswordKey == key
}
