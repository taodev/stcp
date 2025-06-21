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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuthPacket_Encode(t *testing.T) {
	t.Run("successful encoding", func(t *testing.T) {
		// Setup
		password := "testpassword"
		p := &authPacket{}
		p.init(password)
		var buf bytes.Buffer

		// Execute
		err := p.Encode(&buf, password)
		require.NoError(t, err)
		// Verify
		assert.Equal(t, AuthPacketSize, buf.Len())

		p2 := &authPacket{}
		err = p2.Decode(&buf, password)
		require.NoError(t, err)
		assert.Equal(t, p.Nonce, p2.Nonce)
		assert.Equal(t, p.Version, p2.Version)
		assert.Equal(t, p.ClientID, p2.ClientID)
		assert.Equal(t, p.Timestamp, p2.Timestamp)
		assert.Equal(t, p.Sign, p2.Sign)
	})

	t.Run("failed to generate nonce", func(t *testing.T) {
		// Setup
		password := "testpassword"
		p := &authPacket{}
		p.init(password)
		mockWriter := &mockBuffer{}

		// Override rand.Reader to force error
		oldReader := rand.Reader
		defer func() { rand.Reader = oldReader }()
		rand.Reader = &mockBuffer{}
		rand.Reader.(*mockBuffer).On("Read", mock.Anything).Return(0, errors.New("mock rand error"))

		// Execute
		err := p.Encode(mockWriter, password)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mock rand error")
	})

	t.Run("failed to write to writer", func(t *testing.T) {
		// Setup
		password := "testpassword"
		p := &authPacket{}
		p.init(password)
		mockWriter := &mockBuffer{}
		mockWriter.On("Write", mock.Anything).Return(0, errors.New("mock write error"))

		// Execute
		err := p.Encode(mockWriter, password)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mock write error")
	})

	t.Run("verify encryption", func(t *testing.T) {
		// Setup
		password := "testpassword"
		p := &authPacket{}
		p.init(password)
		var buf bytes.Buffer

		// Execute
		err := p.Encode(&buf, password)
		require.NoError(t, err)

		// Verify encryption by decrypting
		key := sha256.Sum256([]byte(fmt.Sprintf("%x-%s", p.Nonce, password)))
		block, err := aes.NewCipher(key[:])
		require.NoError(t, err)

		gcm, err := cipher.NewGCM(block)
		require.NoError(t, err)

		data := buf.Bytes()
		nonce := data[:gcmNonceSize]
		ciphertext := data[gcmNonceSize:]

		decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
		require.NoError(t, err)

		// Verify decrypted content
		expectedContent := make([]byte, 2+2+4+32) // version + timestamp + sign
		binary.BigEndian.PutUint16(expectedContent[:2], p.Version)
		binary.BigEndian.PutUint16(expectedContent[2:4], p.ClientID)
		binary.BigEndian.PutUint32(expectedContent[4:8], p.Timestamp)
		copy(expectedContent[8:], p.Sign[:])

		assert.Equal(t, expectedContent, decrypted)
	})
}

func TestAuthPacket_Decode(t *testing.T) {
	t.Run("successful decode", func(t *testing.T) {
		// Prepare test data
		var expectedPacket authPacket
		var buf bytes.Buffer
		err := expectedPacket.Encode(&buf, "testpassword")
		require.NoError(t, err)

		// Test
		var packet authPacket
		err = packet.Decode(bytes.NewReader(buf.Bytes()), "testpassword")
		assert.NoError(t, err)
		assert.Equal(t, expectedPacket.Nonce, packet.Nonce)
		assert.Equal(t, expectedPacket.Version, packet.Version)
		assert.Equal(t, expectedPacket.ClientID, packet.ClientID)
		assert.Equal(t, expectedPacket.Timestamp, packet.Timestamp)
		assert.Equal(t, expectedPacket.Sign, packet.Sign)
	})

	t.Run("short read", func(t *testing.T) {
		packet := &authPacket{}
		shortBuf := make([]byte, AuthPacketSize-1) // One byte short
		err := packet.Decode(bytes.NewReader(shortBuf), "password")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, io.ErrUnexpectedEOF))
	})

	t.Run("failed to decrypt", func(t *testing.T) {
		var buf bytes.Buffer
		password := "testpassword"
		p1 := &authPacket{}
		p1.init(password)
		err := p1.Encode(&buf, password)
		require.NoError(t, err)

		// error password
		p2 := &authPacket{}
		err = p2.Decode(bytes.NewReader(buf.Bytes()), "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cipher")

		// error nonce
		buf1 := make([]byte, AuthPacketSize)
		copy(buf1, buf.Bytes())
		buf1[0] = 0x01 // change nonce
		buf1[1] = 0x02
		err = p2.Decode(bytes.NewReader(buf1), "testpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cipher")

		// error tag
		copy(buf1, buf.Bytes())
		buf1[AuthPacketSize-1] = 0x01 // change tag
		err = p2.Decode(bytes.NewReader(buf1), "testpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cipher")

		// error body
		copy(buf1, buf.Bytes())
		buf1[gcmNonceSize] = 0x01 // change body
		err = p2.Decode(bytes.NewReader(buf1), "testpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cipher")
	})
}

func TestClientHandshake(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		setupMocks  func(*MockConn)
		wantErr     bool
		expectedErr string
	}{
		{
			name: "successful handshake",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 1 * time.Second,
			},
			setupMocks: func(mockConn *MockConn) {
				mockConn.writer = bytes.NewBuffer(nil)
				// Expect SetWriteDeadline to be called
				mockConn.On("SetWriteDeadline", mock.Anything).Return(nil)
			},
			wantErr: false,
		}, {
			name:   "nil config",
			config: nil,
			setupMocks: func(mockConn *MockConn) {
				// No expectations needed since we fail early
			},
			wantErr:     true,
			expectedErr: "invalid config",
		}, {
			name: "write deadline error",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 50 * time.Millisecond,
			},
			setupMocks: func(mockConn *MockConn) {
				mockConn.wtimeout = time.Now().Add(1 * time.Second)
			},
			wantErr:     true,
			expectedErr: "timeout",
		}, {
			name: "auth packet encode error",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 10 * time.Second,
			},
			setupMocks: func(mockConn *MockConn) {
				mockConn.On("SetWriteDeadline", mock.AnythingOfType("time.Time")).Return(nil)
				mockConn.On("Write", mock.Anything).Return(0, errors.New("encode error"))
			},
			wantErr:     true,
			expectedErr: "encode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := new(MockConn)
			tt.setupMocks(mockConn)

			c := &Conn{
				conn:   mockConn,
				config: tt.config,
			}

			err := c.clientHandshake()

			if tt.wantErr {
				assert.Error(t, err)
				if len(tt.expectedErr) > 0 {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
			}

			mockConn.AssertExpectations(t)
		})
	}
}

func TestServerHandshake(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		setupMocks  func(*MockConn)
		wantErr     bool
		expectedErr string
	}{
		{
			name: "successful handshake",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 1 * time.Second,
			},
			setupMocks: func(mockConn *MockConn) {
				var message authPacket
				message.init("testpass")
				buf := bytes.NewBuffer(nil)
				err := message.Encode(buf, "testpass")
				require.NoError(t, err)

				mockConn.reader = bytes.NewReader(buf.Bytes())
				// Expect SetWriteDeadline to be called
				mockConn.On("SetReadDeadline", mock.Anything).Return(nil)
			},
			wantErr: false,
		}, {
			name:   "nil config",
			config: nil,
			setupMocks: func(mockConn *MockConn) {
				// No expectations needed since we fail early
			},
			wantErr:     true,
			expectedErr: "invalid config",
		}, {
			name: "read deadline error",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 50 * time.Millisecond,
			},
			setupMocks: func(mockConn *MockConn) {
				mockConn.rtimeout = time.Now().Add(1 * time.Second)
			},
			wantErr:     true,
			expectedErr: "timeout",
		}, {
			name: "auth packet decode error",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 10 * time.Second,
			},
			setupMocks: func(mockConn *MockConn) {
				mockConn.On("SetReadDeadline", mock.Anything).Return(nil)
				mockConn.On("Read", mock.Anything).Return(0, errors.New("decode error"))
			},
			wantErr:     true,
			expectedErr: "decode error",
		}, {
			name: "invalid version",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 10 * time.Second,
			},
			setupMocks: func(mockConn *MockConn) {
				message := &authPacket{}
				message.init("testpass")
				message.Version = 0x02

				buf := bytes.NewBuffer(nil)
				err := message.Encode(buf, "testpass")
				require.NoError(t, err)
				mockConn.reader = bytes.NewReader(buf.Bytes())
				mockConn.On("SetReadDeadline", mock.Anything).Return(nil)
			},
			wantErr:     true,
			expectedErr: "invalid version",
		}, {
			name: "invalid timestamp",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 10 * time.Second,
			},
			setupMocks: func(mockConn *MockConn) {
				message := &authPacket{}
				message.init("testpass")
				message.Timestamp = uint32(time.Now().Unix()) - 31

				buf := bytes.NewBuffer(nil)
				err := message.Encode(buf, "testpass")
				require.NoError(t, err)
				mockConn.reader = bytes.NewReader(buf.Bytes())
				mockConn.On("SetReadDeadline", mock.Anything).Return(nil)
			},
			wantErr:     true,
			expectedErr: "handshake timeout",
		}, {
			name: "invalid sign",
			config: &Config{
				Password:         "testpass",
				HandshakeTimeout: 10 * time.Second,
			},
			setupMocks: func(mockConn *MockConn) {
				var message authPacket
				message.init("testpass")
				_, err := io.ReadFull(rand.Reader, message.Sign[:])
				require.NoError(t, err)

				buf := bytes.NewBuffer(nil)
				err = message.Encode(buf, "testpass")
				require.NoError(t, err)
				mockConn.reader = bytes.NewReader(buf.Bytes())
				mockConn.On("SetReadDeadline", mock.Anything).Return(nil)
			},
			wantErr:     true,
			expectedErr: "invalid sign",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := new(MockConn)
			tt.setupMocks(mockConn)

			c := &Conn{
				conn:   mockConn,
				config: tt.config,
			}

			err := c.serverHandshake()

			if tt.wantErr {
				assert.Error(t, err)
				if len(tt.expectedErr) > 0 {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
			}

			mockConn.AssertExpectations(t)
		})
	}
}
