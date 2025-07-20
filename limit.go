package stcp

import "golang.org/x/time/rate"

type LimitConfig struct {
	Limiter      *rate.Limiter `yaml:"-"`
	ReadLimiter  *rate.Limiter `yaml:"-"`
	WriteLimiter *rate.Limiter `yaml:"-"`

	LimitN      int `yaml:"limit"`
	ReadLimitN  int `yaml:"read_limit"`
	WriteLimitN int `yaml:"write_limit"`
}

func (l *LimitConfig) GetReadLimiter() *rate.Limiter {
	if l.ReadLimiter != nil {
		return l.ReadLimiter
	}
	if l.Limiter != nil {
		return l.Limiter
	}
	if l.ReadLimitN > 0 {
		return rate.NewLimiter(rate.Limit(l.ReadLimitN), l.ReadLimitN)
	}
	if l.LimitN > 0 {
		return rate.NewLimiter(rate.Limit(l.LimitN), l.LimitN)
	}
	return nil
}

func (l *LimitConfig) GetWriteLimiter() *rate.Limiter {
	if l.WriteLimiter != nil {
		return l.WriteLimiter
	}
	if l.Limiter != nil {
		return l.Limiter
	}
	if l.WriteLimitN > 0 {
		return rate.NewLimiter(rate.Limit(l.WriteLimitN), l.WriteLimitN)
	}
	if l.LimitN > 0 {
		return rate.NewLimiter(rate.Limit(l.LimitN), l.LimitN)
	}
	return nil
}
