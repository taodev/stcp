package stcp

import (
	"crypto/cipher"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	conn net.Conn

	clientConfig *ClientConfig
	serverCtx    *ServerContext

	gcm cipher.AEAD // AES GCM 实例

	gcmReader *SecureReader
	gcmWriter *SecureWriter

	snappyReader *SnappyReader
	snappyWriter *SnappyWriter

	handshakeFn   func() error
	handshakeOnce sync.Once

	stat *Stat
	rn   int64
	wn   int64

	err error
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
	c.clientConfig = nil
	c.serverCtx = nil

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

func (c *Conn) init(newAEAD newAEAD, key, nonce []byte) error {
	c.stat = WrapStat(c.conn)
	aeadReader, err := newAEAD(key)
	if err != nil {
		return err
	}
	c.gcmReader = NewSecureReader(c.stat, aeadReader, nonce)
	aeadWriter, err := newAEAD(key)
	if err != nil {
		return err
	}
	c.gcmWriter = NewSecureWriter(c.stat, aeadWriter, nonce)
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
