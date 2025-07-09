package stcp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestConn(t *testing.T) {
	clientKey, _ := hex.DecodeString("bd576b064485a8b48e34dd0944dd3103ff41eb25634f9c65210878efad5ff456")
	// clientPub, _ := hex.DecodeString("8eecad2858324bce6c6dc22d3042f8bdcdff1d7ca6505a2d1026334dbfdfcc43")
	serverKey, _ := hex.DecodeString("2ec32e40b1e7db6a890d2177d24062029210bab921bf74f1c4baaf3abde56a7d")
	serverPub, _ := hex.DecodeString("dd5a10ba96106062511848ab9cd91b1eeaf1816698950ef89bfb0cf4e19b8078")

	clientConfig, _ := NewClientConfig()
	clientConfig.PrivateKey = clientKey
	clientConfig.ServerPub = serverPub

	serverCtx, _ := NewServerContext()
	serverCtx.PrivateKey = serverKey

	t.Run("successful", func(t *testing.T) {
		wbuf := &MockConn{}
		wbuf.writer = bytes.NewBuffer(nil)
		wconn := &Conn{
			conn:         wbuf,
			clientConfig: clientConfig,
		}
		wconn.handshakeFn = wconn.clientHandshake
		wbuf.On("SetWriteDeadline", mock.Anything).Return(nil)
		wbuf.On("Close").Return(nil)
		err := wconn.Handshake()
		require.NoError(t, err)
		defer wconn.Close()

		rbuf := &MockConn{}
		rbuf.reader = bytes.NewBuffer(wbuf.writer.(*bytes.Buffer).Bytes())
		rconn := &Conn{
			conn:      rbuf,
			serverCtx: serverCtx,
		}
		rconn.handshakeFn = rconn.serverHandshake
		rbuf.On("SetReadDeadline", mock.Anything).Return(nil)
		rbuf.On("Close").Return(nil)
		err = rconn.Handshake()
		require.NoError(t, err)
		defer rconn.Close()

		wbuf.writer = bytes.NewBuffer(nil)
		n, err := wconn.Write([]byte("hello"))
		require.NoError(t, err)
		require.Equal(t, 5, n)

		rbuf.reader = bytes.NewReader(wbuf.writer.(*bytes.Buffer).Bytes())
		buf := make([]byte, 512)
		n, err = rconn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, 5, n)
		require.Equal(t, "hello", string(buf[:n]))

		wbuf.writer = bytes.NewBuffer(nil)
		longBuf := make([]byte, 1024*6)
		io.ReadFull(rand.Reader, longBuf)
		n, err = wconn.Write(longBuf)
		require.NoError(t, err)
		require.Equal(t, 1024*6, n)

		rbuf.reader = bytes.NewReader(wbuf.writer.(*bytes.Buffer).Bytes())
		buf = make([]byte, 1024*6)
		n, err = rconn.Read(buf[:512])
		require.NoError(t, err)
		require.Equal(t, 512, n)
		require.Equal(t, longBuf[:n], buf[:n])

		n, err = rconn.Read(buf[512:1024])
		require.NoError(t, err)
		require.Equal(t, 512, n)
		require.Equal(t, longBuf[:512+n], buf[:512+n])

		n, err = io.ReadFull(rconn, buf[1024:])
		require.NoError(t, err)
		assert.Equal(t, 1024*6-1024, n)
		assert.Equal(t, longBuf, buf)
	})
}
