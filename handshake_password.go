package stcp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/taodev/pkg/types"
	"github.com/taodev/pkg/util"
)

const (
	hpNonceSize  = 8
	hpNonceStart = 0
	hpNonceEnd   = hpNonceStart + hpNonceSize

	hpSIDSize  = 2
	hpSIDStart = hpNonceEnd
	hpSIDEnd   = hpSIDStart + hpSIDSize

	hpOverheadSize  = 16
	hpOverheadStart = hpSIDEnd
	hpOverheadEnd   = hpOverheadStart + hpOverheadSize

	hpPacketSize = hpOverheadEnd
)

// clientHandshakePassword 使用共享密码代替 ECDH 协商生成会话密钥。
// 报文结构: nonce(8) || seal(sid(2))，其中 seal 输出为 sid 密文 + AEAD tag(16)。
func clientHandshakePassword(w io.Writer, config *ClientConfig) (hi *handshakeInfo, err error) {
	if len(config.Password) == 0 {
		return nil, errors.New("password is empty")
	}

	// crypto type
	newCrypto, nonceSize, err := cryptoFromName(config.CryptoType)
	if err != nil {
		return nil, fmt.Errorf("crypto type error: %w", err)
	}

	var buf [hpPacketSize]byte
	// nonce, 作为密钥派生的 salt, 保证每次握手密钥不同
	if _, err = io.ReadFull(config.Rand, buf[hpNonceStart:hpNonceEnd]); err != nil {
		return nil, fmt.Errorf("read nonce error: %w", err)
	}

	// sid, 用于服务端重放检测
	var sid [hpSIDSize]byte
	if _, err = io.ReadFull(config.Rand, sid[:]); err != nil {
		return nil, fmt.Errorf("read sid error: %w", err)
	}

	// Time window
	var timeWindowBytes [timeWindowSizeV1]byte
	binary.LittleEndian.PutUint64(timeWindowBytes[:], uint64(types.TimeWindow(time.Now().Unix(), config.Tolerance)))
	hexTimeWindow := hex.EncodeToString(timeWindowBytes[:])

	key, err := hkdfKey(sha256.New, []byte(config.Password), buf[hpNonceStart:hpNonceEnd], hexTimeWindow, keySizeV1)
	if err != nil {
		return nil, fmt.Errorf("hkdf error: %w", err)
	}

	aead, err := newCrypto(key)
	if err != nil {
		return nil, fmt.Errorf("new aead error: %w", err)
	}

	// 密钥由 nonce + 时间窗口唯一派生, 此处 seal nonce 使用全零值即可
	sealNonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(buf[hpSIDStart:hpSIDStart], sealNonce, sid[:], nil)
	if len(sealed) != hpSIDSize+hpOverheadSize {
		return nil, errors.New("stcp: unexpected seal size")
	}

	// nonce
	nonce, err := hkdfKey(sha256.New, key, buf[hpSIDStart:hpOverheadEnd], hexTimeWindow, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("nonce error: %w", err)
	}

	if _, err = util.WriteFull(w, buf[:]); err != nil {
		return nil, fmt.Errorf("write error: %w", err)
	}

	return &handshakeInfo{newCrypto: newCrypto, key: key, nonce: nonce}, nil
}

func serverHandshakePassword(r io.Reader, ctx *ServerContext) (hi *handshakeInfo, err error) {
	if len(ctx.Password) == 0 {
		return nil, errors.New("password is empty")
	}

	// crypto type
	newCrypto, nonceSize, err := cryptoFromName(ctx.CryptoType)
	if err != nil {
		return nil, fmt.Errorf("crypto type error: %w", err)
	}

	var buf [hpPacketSize]byte
	// read packet
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	// Time window
	var timeWindowBytes [timeWindowSizeV1]byte
	binary.LittleEndian.PutUint64(timeWindowBytes[:], uint64(types.TimeWindow(time.Now().Unix(), ctx.Tolerance)))
	hexTimeWindow := hex.EncodeToString(timeWindowBytes[:])

	key, err := hkdfKey(sha256.New, []byte(ctx.Password), buf[hpNonceStart:hpNonceEnd], hexTimeWindow, keySizeV1)
	if err != nil {
		return nil, fmt.Errorf("hkdf error: %w", err)
	}

	aead, err := newCrypto(key)
	if err != nil {
		return nil, fmt.Errorf("new aead error: %w", err)
	}

	openNonce := make([]byte, aead.NonceSize())
	sidPlain, err := aead.Open(nil, openNonce, buf[hpSIDStart:hpOverheadEnd], nil)
	if err != nil {
		return nil, errors.New("sign error")
	}

	// 重放攻击判断
	id := uint64(binary.LittleEndian.Uint16(sidPlain))
	if ok := ctx.CheckReplay(id); ok {
		return nil, fmt.Errorf("replay attack: %d", id)
	}

	// nonce
	nonce, err := hkdfKey(sha256.New, key, buf[hpSIDStart:hpOverheadEnd], hexTimeWindow, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("nonce error: %w", err)
	}

	return &handshakeInfo{newCrypto: newCrypto, key: key, nonce: nonce}, nil
}
