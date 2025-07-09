package stcp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"

	"github.com/stretchr/testify/mock"
)

type mockBuffer struct {
	mock.Mock

	writer   io.Writer
	writerFn func([]byte) (int, error)

	reader   io.Reader
	readerFn func([]byte) (int, error)

	directSuccess bool
}

func (buffer *mockBuffer) Write(p []byte) (n int, err error) {
	if buffer.writerFn != nil {
		return buffer.writerFn(p)
	}

	if buffer.writer != nil {
		return buffer.writer.Write(p)
	}

	if buffer.directSuccess {
		return len(p), nil
	}

	args := buffer.Called(p)
	return args.Int(0), args.Error(1)
}

func (b *mockBuffer) Bytes() []byte {
	if b.writer != nil {
		return b.writer.(*bytes.Buffer).Bytes()
	}
	return nil
}

func (buffer *mockBuffer) Read(p []byte) (n int, err error) {
	if buffer.readerFn != nil {
		return buffer.readerFn(p)
	}

	if buffer.reader != nil {
		return buffer.reader.Read(p)
	}

	if buffer.directSuccess {
		return len(p), nil
	}

	args := buffer.Called(p)
	return args.Int(0), args.Error(1)
}

// MockConn is a mock implementation of net.Conn for testing
type MockConn struct {
	mockBuffer

	rtimeout time.Time
	wtimeout time.Time
}

func (m *MockConn) Close() error {
	if m.directSuccess {
		return nil
	}
	args := m.Called()
	return args.Error(0)
}

func (m *MockConn) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) RemoteAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) SetDeadline(t time.Time) error {
	if m.directSuccess {
		return nil
	}

	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	if m.directSuccess {
		return nil
	}

	if !m.rtimeout.IsZero() {
		return nil
	}

	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	if m.directSuccess {
		return nil
	}

	if !m.wtimeout.IsZero() {
		return nil
	}

	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	if !m.directSuccess {
		if !m.rtimeout.IsZero() {
			ch := make(chan int, 1)
			go func() {
				time.Sleep(time.Until(m.rtimeout))
				ch <- 1
			}()

			<-ch
			return 0, errors.New("read timeout")
		}
	}
	return m.mockBuffer.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	if !m.directSuccess {
		if !m.wtimeout.IsZero() {
			ch := make(chan int, 1)
			go func() {
				time.Sleep(time.Until(m.wtimeout))
				ch <- 1
			}()
			<-ch
			return 0, errors.New("write timeout")
		}
	}
	return m.mockBuffer.Write(b)
}
