package keygen

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"

	"github.com/taodev/pkg/types"
)

func PublicKey(privateKey string) (publicKey string, err error) {
	curve := ecdh.X25519()
	var keyBytes types.Binary
	if err = keyBytes.Parse(privateKey); err != nil {
		return
	}
	key, err := curve.NewPrivateKey(keyBytes)
	if err != nil {
		return
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func KeyGen(keyPath string) (publicKey string, err error) {
	curve := ecdh.X25519()
	if _, err = os.Stat(keyPath); err != nil {
		key, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
		if err = os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
			return "", err
		}
		publicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		return publicKey, nil
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	// 去掉空格
	keyString := strings.TrimSpace(string(keyBytes))
	// 去掉换行
	keyString = strings.Trim(keyString, `\n`)
	keyString = strings.Trim(keyString, `\r`)
	// 去掉 tab
	keyString = strings.Trim(keyString, `\t`)
	return PublicKey(keyString)
}

func ReadKey(keyPath string) (key []byte, err error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	// 去掉空格
	keyString := strings.TrimSpace(string(keyBytes))
	// 去掉换行
	keyString = strings.Trim(keyString, `\n`)
	keyString = strings.Trim(keyString, `\r`)
	// 去掉 tab
	keyString = strings.Trim(keyString, `\t`)

	key, err = base64.RawURLEncoding.DecodeString(keyString)
	if err != nil {
		return nil, err
	}
	return key, nil
}
