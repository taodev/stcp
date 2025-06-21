package stcp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type testGCMConn struct {
	name        string
	input       []byte
	setup       func(*mockBuffer)
	done        func(*mockBuffer)
	readDone    func(rdata []byte, reader *GCMReader)
	wantN       int
	wantErr     bool
	wantErrText string
}

func TestGCMWriter_Write(t *testing.T) {
	// Setup AEAD cipher
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	message := make([]byte, gcmPacketSize+100)
	_, err := io.ReadFull(rand.Reader, message)
	require.NoError(t, err)

	tests := []testGCMConn{
		{
			name:    "successful write small packet",
			input:   message[:16],
			wantN:   16,
			wantErr: false,
			setup: func(m *mockBuffer) {
				m.writer = bytes.NewBuffer(nil)
			},
			done: func(m *mockBuffer) {
				buf := m.writer.(*bytes.Buffer).Bytes()
				assert.Equal(t, gcmHeaderSize+16+gcmTagSize, len(buf))

				// 解密对比
				r := NewGCMReader(bytes.NewReader(buf), key)
				defer r.Close()

				rbuf := make([]byte, 4096)
				n, err := r.Read(rbuf)
				assert.NoError(t, err)
				assert.Equal(t, message[:16], rbuf[:n])
			},
		},
		{
			name:    "partial write with retry",
			input:   message[:128],
			wantN:   128,
			wantErr: false,
			setup: func(m *mockBuffer) {
				m.writer = bytes.NewBuffer(nil)
				m.writerFn = func(p []byte) (n int, err error) {
					if len(p) > 4 {
						p = p[:4]
					}
					return m.writer.Write(p)
				}
			},
			done: func(m *mockBuffer) {
				buf := m.writer.(*bytes.Buffer).Bytes()
				assert.Equal(t, gcmHeaderSize+128+gcmTagSize, len(buf))

				// 解密对比
				r := NewGCMReader(bytes.NewReader(buf), key)
				defer r.Close()

				rbuf := make([]byte, 4096)
				n, err := r.Read(rbuf)
				assert.NoError(t, err)
				assert.Equal(t, message[:128], rbuf[:n])
			},
		},
		{
			name:    "successful write large packet truncated",
			input:   message,
			wantN:   len(message),
			wantErr: false,
			setup: func(m *mockBuffer) {
				m.writer = bytes.NewBuffer(nil)
			},
			done: func(m *mockBuffer) {
				buf := m.writer.(*bytes.Buffer).Bytes()
				assert.Equal(t, (gcmHeaderSize+gcmTagSize)*2+len(message), len(buf))

				// 解密对比
				// 读取第一个包
				r := NewGCMReader(bytes.NewReader(buf), key)
				defer r.Close()

				rbuf := make([]byte, gcmPacketSize)
				n, err := r.Read(rbuf)
				assert.NoError(t, err)
				assert.Equal(t, message[:gcmPacketSize], rbuf[:n])

				// 读取第二个包
				rbuf = make([]byte, gcmPacketSize)
				n, err = r.Read(rbuf)
				assert.NoError(t, err)
				assert.Equal(t, message[gcmPacketSize:], rbuf[:n])
			},
		},
		{
			name:        "write error from inner writer",
			input:       []byte("test data"),
			wantN:       0,
			wantErr:     true,
			wantErrText: "write error",
			setup: func(m *mockBuffer) {
				m.On("Write", mock.Anything).Return(0, errors.New("write error")).Once()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInner := new(mockBuffer)
			tt.setup(mockInner)

			w := NewGCMWriter(mockInner, key)
			defer w.Close()

			n, err := w.Write(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				if len(tt.wantErrText) > 0 {
					assert.Contains(t, err.Error(), tt.wantErrText)
				}
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.wantN, n)
			mockInner.AssertExpectations(t)

			if tt.done != nil {
				tt.done(mockInner)
			}
		})
	}

	t.Run("test nonceId overflow", func(t *testing.T) {
		key := []byte{0x01, 0x02, 0x03, 0x04,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14,
		}
		c := NewGCMReader(bytes.NewBuffer(nil), key)
		defer c.Close()

		nonce := c.nextNonce()
		expectedNonce := []byte{0x01, 0x02, 0x03, 0x04,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		}
		assert.Equal(t, expectedNonce, nonce)

		nonce = c.nextNonce()
		expectedNonce = []byte{0x01, 0x02, 0x03, 0x04,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		assert.Equal(t, expectedNonce, nonce)

		nonce = c.nextNonce()
		expectedNonce = []byte{0x01, 0x02, 0x03, 0x04,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		}
		assert.Equal(t, expectedNonce, nonce)
	})
}

func TestNewGCMWriter(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	w := NewGCMWriter(new(mockBuffer), key[:30])
	assert.Nil(t, w)
}

// //////
func TestGCMReader_Read(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	message := make([]byte, gcmPacketSize+100)
	_, err := io.ReadFull(rand.Reader, message)
	require.NoError(t, err)

	tests := []testGCMConn{
		{
			name:    "sucessful read small packet",
			input:   make([]byte, 32),
			wantN:   32,
			wantErr: false,
			setup: func(buffer *mockBuffer) {
				buf := bytes.NewBuffer(nil)
				w := NewGCMWriter(buf, key)
				n, err := w.Write(message[:32])
				require.NoError(t, err)
				require.Equal(t, 32, n)

				buffer.reader = buf
			},
			readDone: func(rdata []byte, reader *GCMReader) {
				assert.Equal(t, rdata, message[:32])
			},
		},
		{
			name:    "sucessful partial write with retry",
			input:   make([]byte, 128),
			wantN:   128,
			wantErr: false,
			setup: func(buffer *mockBuffer) {
				buf := bytes.NewBuffer(nil)
				w := NewGCMWriter(buf, key)
				n, err := w.Write(message[:128])
				require.NoError(t, err)
				require.Equal(t, 128, n)

				buffer.reader = buf
				buffer.readerFn = func(p []byte) (n int, err error) {
					if len(p) > 4 {
						p = p[:4]
					}
					return buffer.reader.Read(p)
				}
			},
			readDone: func(rdata []byte, reader *GCMReader) {
				assert.Equal(t, rdata, message[:128])
			},
		},
		{
			name:    "sucessful reader large packet truncated",
			input:   make([]byte, len(message)),
			wantN:   len(message),
			wantErr: false,
			setup: func(buffer *mockBuffer) {
				buf := bytes.NewBuffer(nil)
				w := NewGCMWriter(buf, key)
				n, err := w.Write(message)
				require.NoError(t, err)
				require.Equal(t, len(message), n)

				buffer.reader = buf
			},
			readDone: func(rdata []byte, reader *GCMReader) {
				assert.Equal(t, rdata, message)
			},
		},
		// 测试一次读不完的情况
		{
			name:    "sucessful reader large packet truncated",
			input:   make([]byte, 1024),
			wantN:   1024,
			wantErr: false,
			setup: func(buffer *mockBuffer) {
				buf := bytes.NewBuffer(nil)
				w := NewGCMWriter(buf, key)
				n, err := w.Write(message)
				require.NoError(t, err)
				require.Equal(t, len(message), n)

				buffer.reader = buf
			},
			readDone: func(rdata []byte, reader *GCMReader) {
				assert.Equal(t, rdata, message[:1024])

				buf := make([]byte, 9000)
				n, err := reader.Read(buf)
				assert.NoError(t, err)
				assert.Equal(t, len(message)-1024, n)
				assert.Equal(t, message[1024:], buf[:n])
			},
		},
		{
			name:        "read EOF",
			input:       make([]byte, 32),
			wantErr:     true,
			wantErrText: "EOF",
			setup: func(buffer *mockBuffer) {
				buffer.On("Read", mock.Anything).Return(0, io.EOF).Once()
			},
		},
		{
			name:        "length zero",
			input:       make([]byte, 32),
			wantErr:     true,
			wantErrText: "EOF",
			setup: func(buffer *mockBuffer) {
				w := bytes.NewBuffer(nil)
				binary.Write(w, binary.BigEndian, uint16(0))
				buffer.reader = w
			},
		},
		{
			name:        "message too long",
			input:       make([]byte, 32),
			wantErr:     true,
			wantErrText: "message too long",
			setup: func(buffer *mockBuffer) {
				w := bytes.NewBuffer(nil)
				binary.Write(w, binary.BigEndian, uint16(gcmPacketCache))
				buffer.reader = w
			},
		},
		{
			name:        "message too short",
			input:       make([]byte, 32),
			wantErr:     true,
			wantErrText: "message too short",
			setup: func(buffer *mockBuffer) {
				w := bytes.NewBuffer(nil)
				binary.Write(w, binary.BigEndian, uint16(15))
				buffer.reader = w
			},
		},
		{
			name:        "read body error",
			input:       make([]byte, 32),
			wantErr:     true,
			wantErrText: io.ErrUnexpectedEOF.Error(),
			setup: func(buffer *mockBuffer) {
				w := bytes.NewBuffer(nil)
				binary.Write(w, binary.BigEndian, uint16(32))
				w.Write([]byte("test data"))
				buffer.reader = w
			},
		},
		{
			name:        "decryption error",
			input:       make([]byte, 32),
			wantErr:     true,
			wantErrText: "cipher",
			setup: func(buffer *mockBuffer) {
				w := bytes.NewBuffer(nil)
				binary.Write(w, binary.BigEndian, uint16(32))
				w.Write([]byte("12345678901234567890123456789012"))
				buffer.reader = w
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInner := new(mockBuffer)
			tt.setup(mockInner)

			r := NewGCMReader(mockInner, key)
			defer r.Close()

			n, err := io.ReadFull(r, tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				if len(tt.wantErrText) > 0 {
					assert.Contains(t, err.Error(), tt.wantErrText)
				}
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.wantN, n)
			mockInner.AssertExpectations(t)

			if tt.done != nil {
				tt.readDone(tt.input, r)
			}
		})
	}
}

func TestNewGCMReader(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	r := NewGCMReader(new(mockBuffer), key[:30])
	assert.Nil(t, r)
}
