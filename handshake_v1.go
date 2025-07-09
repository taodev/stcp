package stcp

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/taodev/pkg/types"
	"github.com/taodev/pkg/util"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keySizeV1  = 32
	keyStartV1 = 0
	keyEndV1   = keyStartV1 + keySizeV1

	idSizeV1  = 8
	idStartV1 = keyEndV1
	idEndV1   = idStartV1 + idSizeV1

	signSizeV1  = 32
	signStartV1 = idEndV1
	signEndV1   = signStartV1 + signSizeV1

	packetSizeV1 = signEndV1

	timeWindowSizeV1 = 8
	maxNonceSize     = chacha20poly1305.NonceSizeX
)

const (
	CryptoAES256GCM         = "aes-256-gcm"
	CryptoChacha20Poly1305  = "chacha20-poly1305"
	CryptoXChacha20Poly1305 = "xchacha20-poly1305"
)

type handshakeInfo struct {
	newCrypto newAEAD
	key       []byte
	nonce     []byte
}

func clientHandshake(w io.Writer, config *ClientConfig) (hi *handshakeInfo, err error) {
	if len(config.ServerPub) == 0 {
		return nil, errors.New("server public key is nil")
	}

	// crypto type
	newCrypto, nonceSize, err := cryptoFromName(config.CryptoType)
	if err != nil {
		return nil, fmt.Errorf("crypto type error: %w", err)
	}

	var sharedKey []byte
	// ecdh 密钥
	curve := ecdh.X25519()
	var privateKey *ecdh.PrivateKey
	if len(config.PrivateKey) > 0 {
		if privateKey, err = curve.NewPrivateKey(config.PrivateKey); err != nil {
			return nil, fmt.Errorf("new private key error: %w", err)
		}
	} else {
		if privateKey, err = curve.GenerateKey(config.Rand); err != nil {
			return nil, fmt.Errorf("generate private key error: %w", err)
		}
	}

	var buf [packetSizeV1]byte
	// public key
	copy(buf[keyStartV1:keyEndV1], privateKey.PublicKey().Bytes())

	// id
	if _, err = io.ReadFull(config.Rand, buf[idStartV1:idEndV1]); err != nil {
		return nil, fmt.Errorf("read id error: %w", err)
	}

	// key
	serverPub, err := curve.NewPublicKey(config.ServerPub)
	if err != nil {
		return nil, fmt.Errorf("server public key error: %w", err)
	}
	if sharedKey, err = ecdhKey(privateKey, serverPub); err != nil {
		return nil, fmt.Errorf("ecdh error: %w", err)
	}
	// Time window
	var timeWindowBytes [timeWindowSizeV1]byte
	binary.LittleEndian.PutUint64(timeWindowBytes[:], uint64(types.TimeWindow(time.Now().Unix(), config.Tolerance)))
	hexTimeWindow := hex.EncodeToString(timeWindowBytes[:])
	key, err := hkdfKey(sha256.New, sharedKey, buf[:idEndV1], hexTimeWindow, keySizeV1)
	if err != nil {
		return nil, fmt.Errorf("hkdf error: %w", err)
	}

	h := hmac.New(sha256.New, key)
	if _, err = hmacWrite(h, buf[:idEndV1]); err != nil {
		return nil, fmt.Errorf("hmac write error: %w", err)
	}
	copy(buf[signStartV1:signEndV1], h.Sum(nil))

	// nonce
	nonce, err := hkdfKey(sha256.New, key, buf[signStartV1:signEndV1], hexTimeWindow, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("nonce error: %w", err)
	}

	if _, err = util.WriteFull(w, buf[:]); err != nil {
		return nil, fmt.Errorf("write error: %w", err)
	}

	return &handshakeInfo{newCrypto: newCrypto, key: key, nonce: nonce}, nil
}

func serverHandshake(r io.Reader, ctx *ServerContext) (hi *handshakeInfo, err error) {
	if len(ctx.PrivateKey) == 0 {
		return nil, errors.New("private key is nil")
	}

	// crypto type
	newCrypto, nonceSize, err := cryptoFromName(ctx.CryptoType)
	if err != nil {
		return nil, fmt.Errorf("crypto type error: %w", err)
	}

	var buf [packetSizeV1]byte
	// read packet
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	idBytes := buf[idStartV1:idEndV1]
	id := binary.LittleEndian.Uint64(idBytes)
	// 重放攻击判断
	if ok := ctx.CheckReplay(id); ok {
		return nil, fmt.Errorf("replay attack: %d", id)
	}

	clientSign := buf[signStartV1:signEndV1]

	// ecdh 密钥
	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(ctx.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key error: %w", err)
	}
	publicKey, err := ecdhNewPublicKey(curve, buf[keyStartV1:keyEndV1])
	if err != nil {
		return nil, fmt.Errorf("public key error: %w", err)
	}
	sharedKey, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh error: %w", err)
	}
	// Time window
	var timeWindowBytes [timeWindowSizeV1]byte
	binary.LittleEndian.PutUint64(timeWindowBytes[:], uint64(types.TimeWindow(time.Now().Unix(), ctx.Tolerance)))
	hexTimeWindow := hex.EncodeToString(timeWindowBytes[:])
	key, err := hkdfKey(sha256.New, sharedKey, buf[:idEndV1], hexTimeWindow, keySizeV1)
	if err != nil {
		return nil, fmt.Errorf("hkdf error: %w", err)
	}
	h := hmac.New(sha256.New, key)
	if _, err = hmacWrite(h, buf[:idEndV1]); err != nil {
		return nil, fmt.Errorf("hmac write error: %w", err)
	}
	sign := h.Sum(nil)
	if !hmac.Equal(sign, clientSign) {
		return nil, errors.New("sign error")
	}

	// nonce
	nonce, err := hkdfKey(sha256.New, key, buf[signStartV1:signEndV1], hexTimeWindow, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("nonce error: %w", err)
	}

	return &handshakeInfo{newCrypto: newCrypto, key: key, nonce: nonce}, nil
}

func cryptoFromName(name string) (newAEAD, int, error) {
	switch name {
	case CryptoAES256GCM:
		return newAES256GCM, gcmNonceSize, nil
	case CryptoChacha20Poly1305:
		return newChacha20Poly1305, chacha20poly1305.NonceSize, nil
	case CryptoXChacha20Poly1305:
		return newXChacha20Poly1305, chacha20poly1305.NonceSizeX, nil
	}
	return nil, 0, errors.New("unsupported crypto type")
}
