package stcp

import (
	"errors"
	"time"
)

const (
	VersionV1 = 0x01
)

func (c *Conn) serverHandshake() (err error) {
	if c.serverCtx == nil {
		return errors.New("stcp: invalid server config")
	}
	if err = c.conn.SetReadDeadline(time.Now().Add(c.serverCtx.HandshakeTimeout)); err != nil {
		return err
	}
	info, err := serverHandshake(c.conn, c.serverCtx)
	if err != nil {
		return err
	}
	if err = c.conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	return c.init(info.newCrypto, info.key, info.nonce)
}

func (c *Conn) clientHandshake() (err error) {
	if c.clientConfig == nil {
		return errors.New("stcp: invalid client config")
	}
	if err = c.conn.SetWriteDeadline(time.Now().Add(c.clientConfig.HandshakeTimeout)); err != nil {
		return err
	}
	info, err := clientHandshake(c.conn, c.clientConfig)
	if err != nil {
		return err
	}
	if err = c.conn.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	return c.init(info.newCrypto, info.key, info.nonce)
}

func (c *Conn) Handshake() error {
	c.handshakeOnce.Do(func() {
		if err := c.handshakeFn(); err != nil {
			c.err = err
		}
	})
	return c.err
}
