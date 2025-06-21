package stcp

import (
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
}

func (buffer *mockBuffer) Write(p []byte) (n int, err error) {
	if buffer.writerFn != nil {
		return buffer.writerFn(p)
	}

	if buffer.writer != nil {
		return buffer.writer.Write(p)
	}

	args := buffer.Called(p)
	return args.Int(0), args.Error(1)
}

func (buffer *mockBuffer) Read(p []byte) (n int, err error) {
	if buffer.readerFn != nil {
		return buffer.readerFn(p)
	}

	if buffer.reader != nil {
		return buffer.reader.Read(p)
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
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	if !m.rtimeout.IsZero() {
		return nil
	}

	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	if !m.wtimeout.IsZero() {
		return nil
	}

	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	if !m.rtimeout.IsZero() {
		ch := make(chan int, 1)
		go func() {
			time.Sleep(time.Until(m.rtimeout))
			ch <- 1
		}()

		<-ch
		return 0, errors.New("read timeout")
	}

	return m.mockBuffer.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	if !m.wtimeout.IsZero() {
		ch := make(chan int, 1)
		go func() {
			time.Sleep(time.Until(m.wtimeout))
			ch <- 1
		}()
		<-ch
		return 0, errors.New("write timeout")
	}

	return m.mockBuffer.Write(b)
}
