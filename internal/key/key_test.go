package key_test

import (
	"testing"

	"github.com/retro-board/key-service/internal/config"
	"github.com/retro-board/key-service/internal/key"
)

func TestKey_GenerateServiceKey(t *testing.T) {
	tests := []struct {
		name   string
		length int
		want   int
	}{
		{
			name:   "test_key_length",
			length: 25,
			want:   25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := key.NewKey(nil)
			res, err := k.GenerateServiceKey(tt.length)
			if err != nil {
				t.Error(err)
			}

			if len(res) != tt.want {
				t.Errorf("Key.GenerateServiceKey() = %v, want %v", len(res), tt.want)
			}
		})
	}
}

func TestKey_ValidateServiceKey(t *testing.T) {
	testKey := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "test_valid_key",
			key:  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: true,
		},
		{
			name: "test_invalid_key",
			key:  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := key.NewKey(&config.Config{
				Local: config.Local{
					OnePasswordKey: testKey,
				},
			})
			if got := k.ValidateServiceKey(tt.key); got != tt.want {
				t.Errorf("Key.ValidateServiceKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKey_GetKeys(t *testing.T) {
	tests := []struct {
		name      string
		want      *key.ResponseItem
		keyLength int
	}{
		{
			name: "test_get_keys",
			want: &key.ResponseItem{
				Status: "ok",
			},
			keyLength: 25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := key.NewKey(nil)
			res, err := k.GetKeys(tt.keyLength)
			if err != nil {
				t.Error(err)
			}

			if res.Status != tt.want.Status {
				t.Errorf("Key.GetKeys() = %v, want %v", res.Status, tt.want.Status)
			}

			if len(res.User) != tt.keyLength {
				t.Errorf("Key.GetKeys() = %v, length = %v, want %v", res.Status, len(res.User), tt.keyLength)
			}
		})
	}
}
