package stcp

import (
	"crypto/aes"
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

type GCMReader struct {
	inner     io.Reader
	gcm       cipher.AEAD
	nonceBase [gcmNonceSize]byte
	nonceId   uint64

	buf   []byte
	rbuf  []byte
	readn int

	err error
}

func (r *GCMReader) Close() error {
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

func (r *GCMReader) nextNonce() []byte {
	nonceId := atomic.AddUint64(&r.nonceId, 1)
	var nonce [gcmNonceSize]byte
	copy(nonce[:4], r.nonceBase[:4])
	binary.BigEndian.PutUint64(nonce[4:], nonceId)
	return nonce[:]
}

func (r *GCMReader) Read(b []byte) (n int, err error) {
	if r.inner == nil {
		return 0, io.ErrClosedPipe
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

func (r *GCMReader) read() (err error) {
	if r.err != nil {
		return r.err
	}
	// 读取消息头
	if _, err = io.ReadFull(r.inner, r.buf[:gcmHeaderSize]); err != nil {
		return
	}

	// 解析消息长度
	rawLen := binary.BigEndian.Uint16(r.buf[:gcmHeaderSize])
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

func NewGCMReader(inner io.Reader, key []byte) *GCMReader {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	r := &GCMReader{
		inner: inner,
		gcm:   gcm,
		buf:   mcache.Malloc(gcmPacketCache),
	}
	copy(r.nonceBase[:4], key[:4])
	r.nonceId = binary.BigEndian.Uint64(key[4:12])
	r.rbuf = r.buf[gcmHeaderSize:]
	return r
}

type GCMWriter struct {
	inner     io.Writer
	gcm       cipher.AEAD
	nonceBase [gcmNonceSize]byte
	nonceId   uint64

	buf []byte

	err error
}

func (w *GCMWriter) Close() error {
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

func (r *GCMWriter) nextNonce() []byte {
	nonceId := atomic.AddUint64(&r.nonceId, 1)
	var nonce [gcmNonceSize]byte
	copy(nonce[:4], r.nonceBase[:4])
	binary.BigEndian.PutUint64(nonce[4:], nonceId)
	return nonce[:]
}

func (w *GCMWriter) Write(b []byte) (n int, err error) {
	if w.inner == nil {
		return 0, io.ErrClosedPipe
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

func (w *GCMWriter) write(b []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(b) > gcmPacketSize {
		b = b[:gcmPacketSize]
	}

	// 写入长度
	rawLen := gcmHeaderSize + len(b) + gcmTagSize
	binary.BigEndian.PutUint16(w.buf[:gcmHeaderSize], uint16(rawLen-gcmHeaderSize))

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

func NewGCMWriter(inner io.Writer, key []byte) *GCMWriter {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	w := &GCMWriter{
		inner: inner,
		gcm:   gcm,
		buf:   mcache.Malloc(gcmPacketCache),
	}
	copy(w.nonceBase[:4], key[:4])
	w.nonceId = binary.BigEndian.Uint64(key[4:12])
	return w
}
