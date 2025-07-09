package stcp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestSecure(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	io.ReadFull(rand.Reader, nonce)
	nonceSize := chacha20poly1305.NonceSize

	var mockR *mockBuffer
	newReader := func(p []byte, key, nonce []byte) *SecureReader {
		aead, err := newAES256GCM(key)
		require.NoError(t, err)

		mockR = &mockBuffer{
			reader: bytes.NewReader(p),
		}
		r := NewSecureReader(mockR, aead, nonce)
		return r
	}

	var mockW *mockBuffer
	newWriter := func(key, nonce []byte) *SecureWriter {
		aead, err := newAES256GCM(key)
		require.NoError(t, err)
		mockW = &mockBuffer{
			writer: bytes.NewBuffer(nil),
		}
		w := NewSecureWriter(mockW, aead, nonce)
		return w
	}

	rbuf := make([]byte, 9*1024)
	wbuf := make([]byte, 8*1024+100)
	io.ReadFull(rand.Reader, wbuf)

	t.Run("successful small packet", func(t *testing.T) {
		dataLen := 16
		w := newWriter(key, nonce[:nonceSize])
		defer w.Close()
		n, err := w.Write(wbuf[:dataLen])
		require.NoError(t, err)
		assert.Equal(t, n, dataLen)
		assert.Equal(t, len(mockW.Bytes()), gcmHeaderSize+dataLen+gcmTagSize)

		r := newReader(mockW.Bytes(), key, nonce[:nonceSize])
		defer r.Close()
		n, err = r.Read(rbuf)
		require.NoError(t, err)
		assert.Equal(t, n, dataLen)
		assert.Equal(t, wbuf[:dataLen], rbuf[:dataLen])
	})

	t.Run("partial with retry", func(t *testing.T) {
		dataLen := 128
		w := newWriter(key, nonce[:nonceSize])
		defer w.Close()
		mockW.writerFn = func(p []byte) (n int, err error) {
			if len(p) > 4 {
				p = p[:4]
			}
			return mockW.writer.Write(p)
		}

		n, err := w.Write(wbuf[:dataLen])
		require.NoError(t, err)
		assert.Equal(t, n, dataLen)
		assert.Equal(t, len(mockW.Bytes()), gcmHeaderSize+dataLen+gcmTagSize)

		r := newReader(mockW.Bytes(), key, nonce[:nonceSize])
		defer r.Close()
		mockR.readerFn = func(p []byte) (n int, err error) {
			if len(p) > 3 {
				p = p[:3]
			}
			return mockR.reader.Read(p)
		}

		n, err = r.Read(rbuf)
		require.NoError(t, err)
		assert.Equal(t, n, dataLen)
		assert.Equal(t, wbuf[:dataLen], rbuf[:dataLen])
	})

	t.Run("successful large packet truncated", func(t *testing.T) {
		dataLen := len(wbuf)
		w := newWriter(key, nonce[:nonceSize])
		defer w.Close()
		n, err := w.Write(wbuf[:dataLen])
		require.NoError(t, err)
		assert.Equal(t, n, dataLen)
		assert.Equal(t, len(mockW.Bytes()), (gcmHeaderSize+gcmTagSize)*int(math.Ceil(float64(dataLen)/float64(gcmPacketSize)))+dataLen)

		r := newReader(mockW.Bytes(), key, nonce[:nonceSize])
		defer r.Close()
		rbuf1 := make([]byte, n)
		nn, err := r.Read(rbuf1[:100])
		require.NoError(t, err)
		assert.Equal(t, nn, 100)
		assert.Equal(t, wbuf[:100], rbuf1[:100])

		n, err = io.ReadFull(r, rbuf1[100:])
		n += nn
		require.NoError(t, err)
		assert.Equal(t, n, dataLen)
		assert.Equal(t, wbuf[:dataLen], rbuf1)
	})

	t.Run("write error from inner writer", func(t *testing.T) {
		dataLen := 16
		w := newWriter(key, nonce[:nonceSize])
		defer w.Close()
		mockW.writer = nil
		mockW.On("Write", mock.Anything).Return(0, errors.New("write error"))
		n, err := w.Write(wbuf[:dataLen])
		require.Error(t, err)
		assert.ErrorContains(t, err, "write error")
		assert.Equal(t, n, 0)
	})

	t.Run("test nonceId overflow", func(t *testing.T) {
		nonce1 := [maxNonceSize]byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		copy(nonce1[idSizeV1:], nonce[idSizeV1:])
		w := newWriter(key, nonce1[:nonceSize])
		defer w.Close()

		nonce := w.nextNonce()
		expectedNonce := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		assert.Equal(t, expectedNonce, nonce[:idSizeV1])
		assert.Equal(t, nonce1[idSizeV1:nonceSize], nonce[idSizeV1:nonceSize])

		nonce = w.nextNonce()
		expectedNonce = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		assert.Equal(t, expectedNonce, nonce[:idSizeV1])
		assert.Equal(t, nonce1[idSizeV1:nonceSize], nonce[idSizeV1:nonceSize])

		nonce = w.nextNonce()
		expectedNonce = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		assert.Equal(t, expectedNonce, nonce[:idSizeV1])
		assert.Equal(t, nonce1[idSizeV1:nonceSize], nonce[idSizeV1:nonceSize])
	})

	t.Run("test write error", func(t *testing.T) {
		w := newWriter(key, nonce[:nonceSize])
		w.err = errors.New("test error")
		_, err := w.Write([]byte{})
		assert.Contains(t, err.Error(), "test error")
		w.err = nil

		w.inner = nil
		_, err = w.Write([]byte{})
		assert.ErrorAs(t, err, &io.ErrClosedPipe)
	})

	t.Run("test read error", func(t *testing.T) {
		r := newReader([]byte{}, key, nonce[:nonceSize])
		r.err = errors.New("test error")
		_, err := r.Read([]byte{})
		assert.Contains(t, err.Error(), "test error")
		r.err = nil

		r.inner = nil
		_, err = r.Read([]byte{})
		assert.ErrorAs(t, err, &io.ErrClosedPipe)

		// read EOF
		r = newReader([]byte{}, key, nonce[:nonceSize])
		_, err = r.Read([]byte{})
		assert.ErrorAs(t, err, &io.EOF)

		wbuf1 := make([]byte, 128)
		rbuf1 := make([]byte, 1024)

		// length zero
		r = newReader(wbuf1, key, nonce[:nonceSize])
		_, err = r.Read(rbuf1)
		assert.ErrorAs(t, err, &io.EOF)

		// message too long
		binary.LittleEndian.PutUint16(wbuf1, gcmPacketCache)
		r = newReader(wbuf1, key, nonce[:nonceSize])
		_, err = r.Read(rbuf1)
		assert.Contains(t, err.Error(), "message too long")

		// message too short
		binary.LittleEndian.PutUint16(wbuf1, 15)
		r = newReader(wbuf1, key, nonce[:nonceSize])
		_, err = r.Read(rbuf1)
		assert.Contains(t, err.Error(), "message too short")

		// read body error
		binary.LittleEndian.PutUint16(wbuf1, 32)
		copy(wbuf1[2:], []byte("test data"))
		r = newReader(wbuf1[:11], key, nonce[:nonceSize])
		_, err = r.Read(rbuf1)
		assert.Contains(t, err.Error(), io.ErrUnexpectedEOF.Error())

		// decryption error
		r = newReader(wbuf1, key, nonce[:nonceSize])
		_, err = r.Read(rbuf1)
		assert.Contains(t, err.Error(), "cipher")
	})
}
