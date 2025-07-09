package stcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	newCipher = aes.NewCipher
	newGCM    = cipher.NewGCM

	newAES256GCM = func(key []byte) (cipher.AEAD, error) {
		block, err := newCipher(key)
		if err != nil {
			return nil, err
		}
		return newGCM(block)
	}

	newChacha20Poly1305  = chacha20poly1305.New
	newXChacha20Poly1305 = chacha20poly1305.NewX

	ecdhKey = func(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
		return privateKey.ECDH(publicKey)
	}

	hkdfKey   = hkdf.Key[hash.Hash]
	hmacWrite = func(h hash.Hash, p []byte) (int, error) {
		return h.Write(p)
	}

	ecdhNewPublicKey = func(curve ecdh.Curve, key []byte) (*ecdh.PublicKey, error) {
		return curve.NewPublicKey(key)
	}
)

type newAEAD func(key []byte) (cipher.AEAD, error)
