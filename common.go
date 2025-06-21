package stcp

import (
	"sync"
	"time"
)

type Config struct {
	ID       uint32
	Password string

	HandshakeTimeout time.Duration

	mutex sync.RWMutex
}

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &Config{
		ID:               c.ID,
		Password:         c.Password,
		HandshakeTimeout: c.HandshakeTimeout,
	}
}
