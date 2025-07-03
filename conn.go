package stcp

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type Conn struct {
	conn   net.Conn
	config *Config

	ClientID uint32

	gcm cipher.AEAD // AES GCM 实例

	gcmReader *GCMReader
	gcmWriter *GCMWriter

	snappyReader *SnappyReader
	snappyWriter *SnappyWriter

	handshakeFn   func() error
	handshakeOnce sync.Once

	stat *Stat
	rn   int64
	wn   int64

	err error
}

func (c *Conn) ID() uint32 {
	return c.ClientID
}

func (c *Conn) LocalAddr() net.Addr {
	if c.err != nil {
		return nil
	}
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.err != nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	if c.err != nil {
		return c.err
	}
	return c.conn.SetDeadline(t)
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.err != nil {
		return c.err
	}
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.err != nil {
		return c.err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) NetConn() net.Conn {
	return c.conn
}

func (c *Conn) Close() (err error) {
	if c.err == nil {
		c.err = io.ErrClosedPipe
	}

	if c.conn != nil {
		err = c.conn.Close()
		c.conn = nil
	}

	c.conn = nil
	c.config = nil

	c.gcm = nil

	if c.gcmReader != nil {
		c.gcmReader.Close()
		c.gcmReader = nil
	}

	if c.gcmWriter != nil {
		c.gcmWriter.Close()
		c.gcmWriter = nil
	}

	c.stat = nil

	return err
}

func (c *Conn) init(message *authPacket) error {
	if c.config == nil || c.config.Password == "" {
		return errors.New("stcp: invalid config, no password")
	}

	c.ClientID = uint32(message.ClientID)

	// 使用 PBKDF2 派生密钥
	salt := []byte(fmt.Sprintf("%x-%d-%d-%s", message.Nonce, message.ClientID, message.Timestamp, c.config.Password))
	key := pbkdf2.Key([]byte(c.config.Password), salt, 4096, 32, sha256.New)

	c.stat = WrapStat(c.conn)
	c.gcmReader = NewGCMReader(c.stat, key[:])
	c.gcmWriter = NewGCMWriter(c.stat, key[:])
	c.snappyReader = NewSnappyReader(c.gcmReader)
	c.snappyWriter = NewSnappyWriter(c.gcmWriter)
	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if c.err != nil {
		return 0, c.err
	}
	n, err = c.snappyReader.Read(b)
	atomic.AddInt64(&c.rn, int64(n))
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if c.err != nil {
		return 0, c.err
	}
	n, err = c.snappyWriter.Write(b)
	atomic.AddInt64(&c.wn, int64(n))
	return
}

func (c *Conn) Stat() (inR, inW, outR, outW int64) {
	if c.stat == nil {
		return
	}
	inR = atomic.LoadInt64(&c.rn)
	inW = atomic.LoadInt64(&c.wn)
	outR, outW = c.stat.Total()
	return
}
