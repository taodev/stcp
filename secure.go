package stcp

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"

	"github.com/bytedance/gopkg/lang/mcache"
)

const (
	gcmHeaderSize  = 2
	gcmNonceSize   = 12
	gcmTagSize     = 16
	gcmPacketSize  = 4 * 1024
	gcmPacketCache = gcmHeaderSize + gcmPacketSize + gcmTagSize
)

type SecureReader struct {
	inner     io.Reader
	gcm       cipher.AEAD
	nonceBase [maxNonceSize]byte
	nonceId   uint64
	nonceSize int

	buf   []byte
	rbuf  []byte
	readn int

	err error
}

func (r *SecureReader) Close() error {
	r.inner = nil
	r.gcm = nil
	r.nonceId = 0

	if r.buf != nil {
		mcache.Free(r.buf)
		r.buf = nil
	}
	r.rbuf = nil

	if r.err == nil {
		r.err = io.ErrClosedPipe
	}
	return r.err
}

func (r *SecureReader) nextNonce() []byte {
	nonceId := atomic.AddUint64(&r.nonceId, 1)
	var nonce [maxNonceSize]byte
	copy(nonce[idSizeV1:r.nonceSize], r.nonceBase[idSizeV1:])
	binary.LittleEndian.PutUint64(nonce[:idSizeV1], nonceId)
	return nonce[:r.nonceSize]
}

func (r *SecureReader) Read(b []byte) (n int, err error) {
	if r.inner == nil {
		return 0, io.ErrClosedPipe
	}
	if r.err != nil {
		return 0, r.err
	}

	if r.readn <= 0 {
		if err = r.read(); err != nil {
			return
		}
	}

	n = copy(b, r.rbuf[:r.readn])
	r.readn -= n
	if r.readn > 0 {
		copy(r.rbuf, r.rbuf[n:n+r.readn])
	}

	return
}

func (r *SecureReader) read() (err error) {
	// 读取消息头
	if _, err = io.ReadFull(r.inner, r.buf[:gcmHeaderSize]); err != nil {
		return
	}

	// 解析消息长度
	rawLen := binary.LittleEndian.Uint16(r.buf[:gcmHeaderSize])
	if rawLen == 0 {
		// 若消息长度为 0，视为读取到文件末尾
		return io.EOF
	}

	if rawLen > gcmPacketCache-gcmHeaderSize {
		// 若消息长度超出最大限制，返回错误
		return errors.New("stcp: message too long")
	}

	if rawLen <= gcmTagSize {
		// 若消息长度小于 GCM 标签长度，返回错误
		return errors.New("stcp: message too short")
	}

	// 读取原始数据
	if _, err = io.ReadFull(r.inner, r.buf[gcmHeaderSize:gcmHeaderSize+rawLen]); err != nil {
		return
	}

	// 解密数据
	// 使用 AES GCM 解密加密消息
	plaintext, err := r.gcm.Open(
		r.rbuf[:0],
		r.nextNonce(),
		r.buf[gcmHeaderSize:gcmHeaderSize+rawLen],
		nil)
	if err != nil {
		return
	}

	r.readn = len(plaintext)
	return
}

func NewSecureReader(inner io.Reader, aead cipher.AEAD, nonce []byte) *SecureReader {
	r := &SecureReader{
		inner: inner,
		gcm:   aead,
		buf:   mcache.Malloc(gcmPacketCache),
	}
	r.nonceSize = aead.NonceSize()
	copy(r.nonceBase[idSizeV1:], nonce[idSizeV1:])
	r.nonceId = binary.LittleEndian.Uint64(nonce[:idSizeV1])
	r.rbuf = r.buf[gcmHeaderSize:]
	return r
}

type SecureWriter struct {
	inner     io.Writer
	gcm       cipher.AEAD
	nonceBase [maxNonceSize]byte
	nonceId   uint64
	nonceSize int

	buf []byte

	err error
}

func (w *SecureWriter) Close() error {
	w.inner = nil
	w.gcm = nil
	w.nonceId = 0

	if w.buf != nil {
		mcache.Free(w.buf)
		w.buf = nil
	}
	if w.err == nil {
		w.err = io.ErrClosedPipe
	}

	return w.err
}

func (w *SecureWriter) nextNonce() []byte {
	nonceId := atomic.AddUint64(&w.nonceId, 1)
	var nonce [maxNonceSize]byte
	copy(nonce[idSizeV1:w.nonceSize], w.nonceBase[idSizeV1:])
	binary.LittleEndian.PutUint64(nonce[:idSizeV1], nonceId)
	return nonce[:w.nonceSize]
}

func (w *SecureWriter) Write(b []byte) (n int, err error) {
	if w.inner == nil {
		return 0, io.ErrClosedPipe
	}
	if w.err != nil {
		return 0, w.err
	}
	writen := 0
	for len(b) > 0 {
		if writen, err = w.write(b); err != nil {
			return
		}
		n += writen
		b = b[writen:]
	}

	return
}

func (w *SecureWriter) write(b []byte) (n int, err error) {
	if len(b) > gcmPacketSize {
		b = b[:gcmPacketSize]
	}

	// 写入长度
	rawLen := gcmHeaderSize + len(b) + gcmTagSize
	binary.LittleEndian.PutUint16(w.buf[:gcmHeaderSize], uint16(rawLen-gcmHeaderSize))

	// 加密数据
	w.gcm.Seal(w.buf[gcmHeaderSize:gcmHeaderSize], w.nextNonce(), b, nil)

	writen := 0
	pos := 0
	p := w.buf[:rawLen]
	for len(p) > 0 {
		if writen, err = w.inner.Write(p); err != nil {
			return
		}

		pos += writen
		p = p[writen:]
	}

	n = len(b)
	return
}

func NewSecureWriter(inner io.Writer, aead cipher.AEAD, nonce []byte) *SecureWriter {
	w := &SecureWriter{
		inner: inner,
		gcm:   aead,
		buf:   mcache.Malloc(gcmPacketCache),
	}
	w.nonceSize = aead.NonceSize()
	copy(w.nonceBase[idSizeV1:], nonce[idSizeV1:])
	w.nonceId = binary.LittleEndian.Uint64(nonce[:idSizeV1])
	return w
}
