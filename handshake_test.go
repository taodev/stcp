package stcp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	clientKey, _ := hex.DecodeString("bd576b064485a8b48e34dd0944dd3103ff41eb25634f9c65210878efad5ff456")
	// clientPub, _ := hex.DecodeString("8eecad2858324bce6c6dc22d3042f8bdcdff1d7ca6505a2d1026334dbfdfcc43")
	serverKey, _ := hex.DecodeString("2ec32e40b1e7db6a890d2177d24062029210bab921bf74f1c4baaf3abde56a7d")
	serverPub, _ := hex.DecodeString("dd5a10ba96106062511848ab9cd91b1eeaf1816698950ef89bfb0cf4e19b8078")

	t.Run("Success", func(t *testing.T) {
		clientConfig, _ := NewClientConfig()
		clientConfig.PrivateKey = clientKey
		clientConfig.ServerPub = serverPub

		serverCtx, _ := NewServerContext()
		serverCtx.PrivateKey = serverKey
		defer serverCtx.Close()

		buf := bytes.NewBuffer(nil)
		clientConn := &MockConn{
			mockBuffer: mockBuffer{
				writer:        buf,
				directSuccess: true,
			},
		}

		c := Client(clientConn, clientConfig)
		err := c.Handshake()
		assert.NoError(t, err)

		serverConn := &MockConn{
			mockBuffer: mockBuffer{
				reader:        bytes.NewReader(buf.Bytes()),
				directSuccess: true,
			},
		}

		s := Server(serverConn, serverCtx)
		err = s.Handshake()
		assert.NoError(t, err)
	})

	t.Run("clientHandshake Error", func(t *testing.T) {
		clientConfig, _ := NewClientConfig()
		clientConfig.PrivateKey = clientKey
		clientConfig.ServerPub = serverPub
		conn := &MockConn{}

		c := Client(conn, nil)
		err := c.clientHandshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid client config")

		c.clientConfig = clientConfig
		conn.On("SetWriteDeadline", mock.Anything).Return(errors.New("mock error")).Once()
		err = c.clientHandshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "mock error")

		conn.On("SetWriteDeadline", mock.Anything).Return(nil).Once()
		conn.On("Write", mock.Anything).Return(0, errors.New("mock error")).Once()
		err = c.clientHandshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "mock error")

		conn.On("SetWriteDeadline", mock.Anything).Return(nil).Once()
		conn.On("SetWriteDeadline", mock.Anything).Return(errors.New("mock error")).Once()
		conn.writer = bytes.NewBuffer(nil)
		err = c.Handshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "mock error")
	})

	t.Run("serverHandshake Error", func(t *testing.T) {
		serverCtx, _ := NewServerContext()
		serverCtx.PrivateKey = serverKey
		defer serverCtx.Close()
		conn := &MockConn{}

		c := Server(conn, nil)
		err := c.serverHandshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid server config")

		c.serverCtx = serverCtx
		conn.On("SetReadDeadline", mock.Anything).Return(errors.New("mock error")).Once()
		err = c.serverHandshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "mock error")

		conn.On("SetReadDeadline", mock.Anything).Return(nil).Once()
		conn.On("Read", mock.Anything).Return(0, errors.New("mock error")).Once()
		err = c.serverHandshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "mock error")

		clientConfig, _ := NewClientConfig()
		clientConfig.PrivateKey = clientKey
		clientConfig.ServerPub = serverPub
		buf := bytes.NewBuffer(nil)
		client := Client(&MockConn{
			mockBuffer: mockBuffer{
				writer:        buf,
				directSuccess: true,
			},
		}, clientConfig)
		err = client.Handshake()
		require.NoError(t, err)

		conn.On("SetReadDeadline", mock.Anything).Return(nil).Once()
		conn.On("SetReadDeadline", mock.Anything).Return(errors.New("mock error")).Once()
		conn.reader = bytes.NewReader(buf.Bytes())
		err = c.serverHandshake()
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "mock error")
	})
}
