package key

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"strings"

	"github.com/taodev/pkg/types"
)

func ToBase64(key types.Binary) string {
	return key.String()
}

func Base64(v string) (key types.Binary, err error) {
	err = key.Parse(v)
	return key, err
}

func PublicKey(key types.Binary) (publicKey types.Binary, err error) {
	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return privateKey.PublicKey().Bytes(), nil
}

func Generate(keyPath string) (privateKey types.Binary, err error) {
	curve := ecdh.X25519()
	if _, err = os.Stat(keyPath); err != nil {
		key, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		privateKey = key.Bytes()
		err = os.WriteFile(keyPath, []byte(privateKey.String()), 0600)
		return privateKey, err
	}
	return Read(keyPath)
}

func Read(keyPath string) (key types.Binary, err error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	err = key.Parse(strings.TrimSpace(string(keyBytes)))
	return key, err
}
