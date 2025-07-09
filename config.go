package stcp

import (
	"crypto/rand"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/taodev/pkg/defaults"
)

type ClientConfig struct {
	Rand io.Reader `yaml:"-"`

	// 握手超时时间
	HandshakeTimeout time.Duration `yaml:"handshake_timeout" default:"30s"`
	// 容忍时间窗口 (秒)
	Tolerance int64 `yaml:"tolerance" default:"120"`

	// ECDH
	// 私钥: 使用 ecdh, 推荐
	PrivateKey []byte `yaml:"private_key"`
	// 服务端公钥
	ServerPub []byte `yaml:"server_pub"`

	// 加密类型
	// 支持 aes-256-gcm, chacha20-poly1305, xchacha20-poly1305
	CryptoType string `yaml:"crypto_type" default:"aes-256-gcm"`
}

type ServerContext struct {
	Rand io.Reader `yaml:"-"`

	// 握手超时时间
	HandshakeTimeout time.Duration `yaml:"handshake_timeout" default:"30s"`
	// 容忍时间窗口 (秒)
	Tolerance int64 `yaml:"tolerance" default:"120"`
	// 最大并发数
	MaxConns int `yaml:"max_conns" default:"1024"`

	// ECDH
	// 私钥: 使用 ecdh, 推荐
	PrivateKey []byte `yaml:"private_key"`

	// 公钥认证: 使用 ecdh, 推荐
	AuthorizedKeys [][]byte `yaml:"authorized_keys"`
	AuthorizedPath string   `yaml:"authorized_path"`

	// 加密类型
	// 支持 aes-256-gcm, chacha20-poly1305, xchacha20-poly1305
	CryptoType string `yaml:"crypto_type" default:"aes-256-gcm"`

	idMap     map[uint64]int64 `yaml:"-"`
	idMutex   sync.RWMutex     `yaml:"-"`
	closeCh   chan struct{}    `yaml:"-"`
	closeOnce sync.Once
	wait      sync.WaitGroup
	running   atomic.Bool
}

func NewClientConfig() (cfg *ClientConfig, err error) {
	cfg = new(ClientConfig)
	cfg.Rand = rand.Reader
	if err = defaults.Set(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func NewServerContext() (ctx *ServerContext, err error) {
	ctx = new(ServerContext)
	ctx.Rand = rand.Reader
	ctx.idMap = make(map[uint64]int64)
	ctx.closeCh = make(chan struct{})
	if err = defaults.Set(ctx); err != nil {
		return nil, err
	}
	ctx.wait.Add(1)
	ctx.running.Store(true)
	go ctx.replayGC()
	return ctx, nil
}

func (ctx *ServerContext) CheckReplay(id uint64) bool {
	if !ctx.running.Load() {
		return true
	}
	ctx.idMutex.Lock()
	defer ctx.idMutex.Unlock()
	_, ok := ctx.idMap[id]

	if !ok {
		ctx.idMap[id] = time.Now().Unix()
		return false
	}
	return true
}

func (ctx *ServerContext) replayGC() {
	defer ctx.wait.Done()
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			ctx.idMutex.Lock()
			for id, t := range ctx.idMap {
				if now-t > ctx.Tolerance {
					delete(ctx.idMap, id)
				}
			}
			ctx.idMutex.Unlock()
		case <-ctx.closeCh:
			ticker.Stop()
			return
		}
	}
}

func (ctx *ServerContext) Close() {
	ctx.closeOnce.Do(func() {
		ctx.running.Store(false)
		close(ctx.closeCh)
		ctx.wait.Wait()
	})
}
