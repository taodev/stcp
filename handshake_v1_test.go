package stcp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockRander struct {
	mustLen int
}

func (m *mockRander) Read(b []byte) (n int, err error) {
	if m.mustLen != len(b) {
		return rand.Reader.Read(b)
	}
	return 0, errors.New("rand error")
}

func TestHandshakeV1(t *testing.T) {
	clientKey, _ := hex.DecodeString("bd576b064485a8b48e34dd0944dd3103ff41eb25634f9c65210878efad5ff456")
	clientPub, _ := hex.DecodeString("8eecad2858324bce6c6dc22d3042f8bdcdff1d7ca6505a2d1026334dbfdfcc43")
	serverKey, _ := hex.DecodeString("2ec32e40b1e7db6a890d2177d24062029210bab921bf74f1c4baaf3abde56a7d")
	serverPub, _ := hex.DecodeString("dd5a10ba96106062511848ab9cd91b1eeaf1816698950ef89bfb0cf4e19b8078")

	successTest := func(t *testing.T, cryptoType string, nonceSize int) {
		clientConfig, _ := NewClientConfig()
		clientConfig.PrivateKey = clientKey
		clientConfig.ServerPub = serverPub

		serverCtx, _ := NewServerContext()
		serverCtx.PrivateKey = serverKey
		defer serverCtx.Close()

		clientConfig.CryptoType = cryptoType
		serverCtx.CryptoType = cryptoType
		w := bytes.NewBuffer(nil)
		clientInfo, err := clientHandshake(w, clientConfig)
		require.NoError(t, err)
		wbuf := w.Bytes()
		assert.Equal(t, clientPub, wbuf[keyStartV1:keyEndV1])
		// assert.True(t, clientInfo.newCrypto == newAES256GCM)
		assert.Equal(t, len(clientInfo.nonce), nonceSize)
		assert.Equal(t, len(clientInfo.key), 32)

		r := bytes.NewReader(wbuf)
		serverInfo, err := serverHandshake(r, serverCtx)
		require.NoError(t, err)
		// assert.Equal(t, serverInfo.newCrypto, clientInfo.newCrypto)
		assert.Equal(t, serverInfo.nonce, clientInfo.nonce)
		assert.Equal(t, serverInfo.key, clientInfo.key)

		testData := []byte("test data")
		aeadClient, err := clientInfo.newCrypto(clientInfo.key)
		require.NoError(t, err)
		aeadServer, err := serverInfo.newCrypto(serverInfo.key)
		require.NoError(t, err)

		encryptedData := aeadClient.Seal(nil, clientInfo.nonce, testData, nil)
		decryptedData, err := aeadServer.Open(nil, serverInfo.nonce, encryptedData, nil)
		assert.NoError(t, err)
		assert.Equal(t, testData, decryptedData)
	}
	t.Run("Success", func(t *testing.T) {
		successTest(t, CryptoAES256GCM, gcmNonceSize)
		successTest(t, CryptoChacha20Poly1305, gcmNonceSize)
		successTest(t, CryptoXChacha20Poly1305, maxNonceSize)
	})

	t.Run("Handshake timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping Handshake timeout")
		}
		clientConfig, _ := NewClientConfig()
		clientConfig.PrivateKey = clientKey
		clientConfig.ServerPub = serverPub
		clientConfig.Tolerance = 1

		serverCtx, _ := NewServerContext()
		serverCtx.PrivateKey = serverKey
		serverCtx.Tolerance = 1
		defer serverCtx.Close()

		buf := bytes.NewBuffer(nil)
		_, err := clientHandshake(buf, clientConfig)
		require.NoError(t, err)
		time.Sleep(1 * time.Second)
		_, err = serverHandshake(bytes.NewReader(buf.Bytes()), serverCtx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sign error")
	})

	t.Run("ClientHandshake Error", func(t *testing.T) {
		cfg, _ := NewClientConfig()

		info, err := clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "key is nil")
		assert.Nil(t, info)

		cfg.ServerPub = serverPub
		cfg.CryptoType = "xxxxxx"
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "crypto type error")
		assert.Nil(t, info)

		cfg.CryptoType = CryptoAES256GCM
		cfg.PrivateKey = []byte{0x00, 0x01}
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "new private key error")
		assert.Nil(t, info)

		mockRand := &mockBuffer{}
		cfg.PrivateKey = nil
		cfg.Rand = mockRand
		mockRand.On("Read", mock.Anything).Return(0, errors.New("rand error"))
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "generate private key error")
		assert.Nil(t, info)

		rander := &mockRander{}
		rander.mustLen = idSizeV1
		cfg.Rand = rander
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "read id error")
		assert.Nil(t, info)

		cfg.Rand = rand.Reader
		cfg.ServerPub = []byte{0x00, 0x01}
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "server public key error")
		assert.Nil(t, info)

		ecdhKeyOld := ecdhKey
		ecdhKey = func(*ecdh.PrivateKey, *ecdh.PublicKey) ([]byte, error) {
			return nil, errors.New("ecdh error")
		}
		cfg.ServerPub = serverPub
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "ecdh error")
		assert.Nil(t, info)
		ecdhKey = ecdhKeyOld

		hkdfKeyOld := hkdfKey
		hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
			return nil, errors.New("hkdf error")
		}
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "hkdf error")
		assert.Nil(t, info)
		hkdfKey = hkdfKeyOld

		hmacWriteOld := hmacWrite
		hmacWrite = func(h hash.Hash, p []byte) (int, error) {
			return 0, errors.New("hmac error")
		}
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "hmac write error")
		assert.Nil(t, info)
		hmacWrite = hmacWriteOld

		hkdfKeyOld = hkdfKey
		hkdfKeyCallN := 0
		hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
			if hkdfKeyCallN <= 0 {
				hkdfKeyCallN++
				return hkdfKeyOld(h, secret, salt, info, keyLength)
			}
			return nil, errors.New("hkdf error")
		}
		info, err = clientHandshake(nil, cfg)
		assert.Contains(t, err.Error(), "nonce error")
		assert.Nil(t, info)
		hkdfKey = hkdfKeyOld

		mockWriter := &mockBuffer{}
		mockWriter.On("Write", mock.Anything).Return(0, errors.New("write error")).Once()
		info, err = clientHandshake(mockWriter, cfg)
		assert.Contains(t, err.Error(), "write error")
		assert.Nil(t, info)
	})

	t.Run("ServerHandshake Error", func(t *testing.T) {
		clientConfig, _ := NewClientConfig()
		clientConfig.PrivateKey = clientKey
		clientConfig.ServerPub = serverPub
		ctx, _ := NewServerContext()

		info, err := serverHandshake(nil, ctx)
		assert.Contains(t, err.Error(), "private key is nil")
		assert.Nil(t, info)

		ctx.PrivateKey = serverKey
		ctx.CryptoType = "xxxxxx"
		info, err = serverHandshake(nil, ctx)
		assert.Contains(t, err.Error(), "crypto type error")
		assert.Nil(t, info)
		ctx.CryptoType = CryptoAES256GCM

		mockReader := &mockBuffer{}
		mockReader.On("Read", mock.Anything).Return(0, errors.New("read error")).Once()
		info, err = serverHandshake(mockReader, ctx)
		assert.Contains(t, err.Error(), "read error")
		assert.Nil(t, info)

		var buf [packetSizeV1]byte
		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x02)
		ctx.idMap[0x02] = time.Now().Unix()
		info, err = serverHandshake(bytes.NewReader(buf[:]), ctx)
		assert.Contains(t, err.Error(), "replay attack")
		assert.Nil(t, info)

		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x03)
		ctx.PrivateKey = []byte{0x01, 0x02}
		info, err = serverHandshake(bytes.NewReader(buf[:]), ctx)
		assert.Contains(t, err.Error(), "private key error")
		assert.Nil(t, info)
		ctx.PrivateKey = serverKey

		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x05)
		ecdhNewPublicKeyOld := ecdhNewPublicKey
		ecdhNewPublicKey = func(curve ecdh.Curve, key []byte) (*ecdh.PublicKey, error) {
			return nil, errors.New("public key error")
		}
		info, err = serverHandshake(bytes.NewReader(buf[:]), ctx)
		assert.Contains(t, err.Error(), "public key error")
		assert.Nil(t, info)
		ecdhNewPublicKey = ecdhNewPublicKeyOld

		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x06)
		info, err = serverHandshake(bytes.NewReader(buf[:]), ctx)
		assert.Contains(t, err.Error(), "ecdh error")
		assert.Nil(t, info)

		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x07)
		copy(buf[keyStartV1:keyEndV1], clientPub)
		io.ReadFull(ctx.Rand, buf[keyEndV1:keyEndV1])
		hkdfKeyOld := hkdfKey
		hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
			return nil, errors.New("hkdf error")
		}
		info, err = serverHandshake(bytes.NewReader(buf[:]), ctx)
		assert.Contains(t, err.Error(), "hkdf error")
		assert.Nil(t, info)
		hkdfKey = hkdfKeyOld

		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x08)
		hmacWriteOld := hmacWrite
		hmacWrite = func(h hash.Hash, p []byte) (int, error) {
			return 0, errors.New("hmac error")
		}
		info, err = serverHandshake(bytes.NewReader(buf[:]), ctx)
		assert.Contains(t, err.Error(), "hmac write error")
		assert.Nil(t, info)
		hmacWrite = hmacWriteOld

		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x09)
		info, err = serverHandshake(bytes.NewReader(buf[:]), ctx)
		assert.Contains(t, err.Error(), "sign error")
		assert.Nil(t, info)

		binary.LittleEndian.PutUint64(buf[idStartV1:idEndV1], 0x10)
		w := bytes.NewBuffer(nil)
		_, err = clientHandshake(w, clientConfig)
		require.NoError(t, err)
		hkdfKeyOld = hkdfKey
		hkdfKeyCallN := 0
		hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
			if hkdfKeyCallN <= 0 {
				hkdfKeyCallN++
				return hkdfKeyOld(h, secret, salt, info, keyLength)
			}
			return nil, errors.New("hkdf error")
		}
		info, err = serverHandshake(bytes.NewReader(w.Bytes()), ctx)
		assert.Contains(t, err.Error(), "nonce error")
		assert.Nil(t, info)
		hkdfKey = hkdfKeyOld
	})
}
