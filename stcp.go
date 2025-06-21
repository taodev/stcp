package stcp

import (
	"context"
	"errors"
	"net"
)

func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	c.handshakeFn = c.serverHandshake
	return c
}

func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	c.handshakeFn = c.clientHandshake

	// if err := c.clientHandshake(); err != nil {
	// 	conn.Close()
	// 	return nil, err
	// }

	return c
}

type listener struct {
	net.Listener
	config *Config
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen 函数用于在指定的网络和地址上创建一个新的监听器。
// 该监听器会使用提供的配置信息，对传入的连接进行处理。
// 参数 network 表示网络类型，例如 "tcp"、"udp" 等。
// 参数 address 表示监听的地址，例如 "localhost:8080"。
// 参数 config 表示 stcp 连接的配置信息。
// 返回值 net.Listener 是创建好的监听器，error 表示可能出现的错误。
func Listen(network, address string, config *Config) (net.Listener, error) {
	// 检查配置是否有效，若配置为空或者密码为空，则返回错误
	if config == nil || len(config.Password) <= 0 {
		return nil, errors.New("stcp: invalid config, nor password")
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	// 检查配置是否有效，若配置为空或者密码为空，则返回错误
	if config == nil || len(config.Password) <= 0 {
		return nil, errors.New("stcp: invalid config, nor password")
	}

	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}

	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	conn := Client(rawConn, config)
	if err := conn.handshakeFn(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

type Dialer struct {
	NetDialer *net.Dialer
	Config    *Config
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		return nil, err
	}
	return c, nil
}
