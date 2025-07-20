package stcp

import (
	"context"
	"net"
	"sync/atomic"

	"golang.org/x/time/rate"
)

type Stat struct {
	net.Conn

	rn int64
	wn int64

	rL *rate.Limiter
	wL *rate.Limiter
}

func WrapStat(c net.Conn) *Stat {
	return &Stat{
		Conn: c,
	}
}

func (s *Stat) Read(p []byte) (n int, err error) {
	n, err = s.Conn.Read(p)
	if n > 0 && s.rL != nil {
		s.rL.WaitN(context.Background(), n)
	}
	atomic.AddInt64(&s.rn, int64(n))
	return
}

func (s *Stat) Write(p []byte) (n int, err error) {
	n, err = s.Conn.Write(p)
	if n > 0 && s.wL != nil {
		s.wL.WaitN(context.Background(), n)
	}
	atomic.AddInt64(&s.wn, int64(n))
	return
}

func (s *Stat) Total() (rn, wn int64) {
	rn = atomic.LoadInt64(&s.rn)
	wn = atomic.LoadInt64(&s.wn)
	return
}
