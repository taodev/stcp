package stcp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

type authPacket struct {
	Nonce     [gcmNonceSize]byte
	Version   uint16
	ClientID  uint16
	Timestamp uint32
	Sign      [32]byte
}

const (
	Version        = 0x01
	AuthPacketSize = gcmNonceSize + 2 + 2 + 4 + 32 + gcmTagSize
)

func (p *authPacket) init(password string) {
	p.Version = Version
	p.ClientID = 0
	p.Timestamp = uint32(time.Now().Unix())
	p.Sign = sha256.Sum256([]byte(
		fmt.Sprintf("%d-%d-%d-%s", p.Version, p.ClientID, p.Timestamp, password),
	))
}

func (p *authPacket) Encode(w io.Writer, password string) (err error) {
	if _, err = io.ReadFull(rand.Reader, p.Nonce[:]); err != nil {
		return
	}

	var buf [AuthPacketSize]byte
	n := copy(buf[:gcmNonceSize], p.Nonce[:])
	binary.BigEndian.PutUint16(buf[n:], p.Version)
	n += 2
	binary.BigEndian.PutUint16(buf[n:], p.ClientID)
	n += 2
	binary.BigEndian.PutUint32(buf[n:], p.Timestamp)
	n += 4
	n += copy(buf[n:], p.Sign[:])

	// 加密
	key := sha256.Sum256([]byte(fmt.Sprintf("%x-%s", p.Nonce, password)))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	gcm.Seal(buf[gcmNonceSize:gcmNonceSize], p.Nonce[:], buf[gcmNonceSize:n], nil)

	_, err = w.Write(buf[:])
	return
}

func (p *authPacket) Decode(r io.Reader, password string) (err error) {
	var buf [AuthPacketSize]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return
	}

	n := copy(p.Nonce[:], buf[:gcmNonceSize])
	// 解密
	key := sha256.Sum256([]byte(fmt.Sprintf("%x-%s", p.Nonce, password)))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	_, err = gcm.Open(buf[gcmNonceSize:gcmNonceSize], p.Nonce[:], buf[gcmNonceSize:], nil)
	if err != nil {
		return
	}

	p.Version = binary.BigEndian.Uint16(buf[n:])
	n += 2
	p.ClientID = binary.BigEndian.Uint16(buf[n:])
	n += 2
	p.Timestamp = binary.BigEndian.Uint32(buf[n:])
	n += 4
	copy(p.Sign[:], buf[n:])

	return
}

func (c *Conn) serverHandshake() error {
	if c.config == nil || c.config.Password == "" {
		return errors.New("stcp: invalid config, nor password")
	}

	if c.config.HandshakeTimeout == 0 {
		c.config.HandshakeTimeout = 30 * time.Second
	}

	// 读取握手消息
	var message authPacket
	c.conn.SetReadDeadline(time.Now().Add(c.config.HandshakeTimeout))
	if err := message.Decode(c.conn, c.config.Password); err != nil {
		return err
	}
	// 重置读超时
	c.conn.SetReadDeadline(time.Time{})

	// 解析握手消息
	// 版本号
	if message.Version != Version {
		return errors.New("stcp: invalid version")
	}

	// 检查时间戳是否过期
	if math.Abs(float64(time.Now().Unix())-float64(message.Timestamp)) > 30 {
		return errors.New("stcp: handshake timeout")
	}

	// 验证签名
	var signInput string = fmt.Sprintf("%d-%d-%d-%s", message.Version, message.ClientID, message.Timestamp, c.config.Password)
	var checkSum = sha256.Sum256([]byte(signInput))

	if !bytes.Equal(checkSum[:], message.Sign[:]) {
		return errors.New("stcp: invalid sign")
	}

	return c.init(&message)
}

func (c *Conn) clientHandshake() error {
	if c.config == nil || c.config.Password == "" {
		return errors.New("stcp: invalid config, nor password")
	}

	if c.config.HandshakeTimeout == 0 {
		c.config.HandshakeTimeout = 30 * time.Second
	}

	// 发送握手消息
	c.conn.SetWriteDeadline(time.Now().Add(c.config.HandshakeTimeout))
	var message authPacket
	message.init(c.config.Password)
	message.ClientID = uint16(c.ClientID)
	if err := message.Encode(c.conn, c.config.Password); err != nil {
		return err
	}
	c.conn.SetWriteDeadline(time.Time{})

	return c.init(&message)
}

func (c *Conn) Handshake() error {
	c.handshakeOnce.Do(func() {
		if err := c.handshakeFn(); err != nil {
			c.err = err
		}
	})
	return c.err
}
