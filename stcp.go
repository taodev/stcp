package stcp

import (
	"context"
	"errors"
	"net"
)

func Server(conn net.Conn, ctx *ServerContext) *Conn {
	if len(ctx.PrivateKey) == 0 {
		ctx.PrivateKey = PrivateKey()
	}

	c := &Conn{
		conn:      conn,
		serverCtx: ctx,
	}
	c.handshakeFn = c.serverHandshake
	return c
}

func Client(conn net.Conn, config *ClientConfig) *Conn {
	if len(config.PrivateKey) == 0 {
		config.PrivateKey = PrivateKey()
	}
	if len(config.ServerPub) == 0 {
		config.ServerPub = HostKey(conn.RemoteAddr().String())
	}
	c := &Conn{
		conn:         conn,
		clientConfig: config,
	}
	c.handshakeFn = c.clientHandshake
	return c
}

type listener struct {
	net.Listener
	ctx *ServerContext
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.ctx), nil
}

func (l *listener) Close() error {
	err := l.Listener.Close()
	if err != nil {
		return err
	}
	l.ctx.Close()
	return nil
}

func NewListener(inner net.Listener, ctx *ServerContext) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.ctx = ctx
	return l
}

// Listen 函数用于在指定的网络和地址上创建一个新的监听器。
// 该监听器会使用提供的配置信息，对传入的连接进行处理。
// 参数 network 表示网络类型，例如 "tcp"、"udp" 等。
// 参数 address 表示监听的地址，例如 "localhost:8080"。
// 参数 config 表示 stcp 连接的配置信息。
// 返回值 net.Listener 是创建好的监听器，error 表示可能出现的错误。
func Listen(network, address string, ctx *ServerContext) (net.Listener, error) {
	// 检查配置是否有效，若配置为空则返回错误
	if ctx == nil {
		return nil, errors.New("stcp: invalid ctx")
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return NewListener(l, ctx), nil
}

func DialWithDialer(dialer *net.Dialer, network, addr string, config *ClientConfig) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *ClientConfig) (*Conn, error) {
	// 检查配置是否有效，若配置为空则返回错误
	if config == nil {
		return nil, errors.New("stcp: invalid config")
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
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

func Dial(network, addr string, config *ClientConfig) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

type Dialer struct {
	NetDialer *net.Dialer
	Config    *ClientConfig
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
