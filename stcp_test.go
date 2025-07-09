package stcp

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// var testConfig = &Config{
// 	ID:       1,
// 	Password: "testpassword",
// }

func newLocalListener(t testing.TB) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestSTCP(t *testing.T) {
	clientKey, _ := hex.DecodeString("bd576b064485a8b48e34dd0944dd3103ff41eb25634f9c65210878efad5ff456")
	// clientPub, _ := hex.DecodeString("8eecad2858324bce6c6dc22d3042f8bdcdff1d7ca6505a2d1026334dbfdfcc43")
	serverKey, _ := hex.DecodeString("2ec32e40b1e7db6a890d2177d24062029210bab921bf74f1c4baaf3abde56a7d")
	serverPub, _ := hex.DecodeString("dd5a10ba96106062511848ab9cd91b1eeaf1816698950ef89bfb0cf4e19b8078")

	clientConfig, _ := NewClientConfig()
	clientConfig.PrivateKey = clientKey
	clientConfig.ServerPub = serverPub

	serverCtx, _ := NewServerContext()
	serverCtx.PrivateKey = serverKey

	t.Run("dial timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode.")
		}

		timeout := 100 * time.Microsecond
		for !t.Failed() {
			acceptc := make(chan net.Conn)
			listener := newLocalListener(t)
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						close(acceptc)
						return
					}
					acceptc <- conn
				}
			}()

			addr := listener.Addr().String()
			dialer := &net.Dialer{
				Timeout: timeout,
			}
			if conn, err := DialWithDialer(dialer, "tcp", addr, clientConfig); err == nil {
				conn.Close()
				t.Errorf("DialWithTimeout unexpectedly completed successfully")
			} else if !isTimeoutError(err) {
				t.Errorf("resulting error not a timeout: %v\nType %T: %#v", err, err, err)
			}

			listener.Close()

			lconn, ok := <-acceptc
			if ok {
				// The Listener accepted a connection, so assume that it was from our
				// Dial: we triggered the timeout at the point where we wanted it!
				t.Logf("Listener accepted a connection from %s", lconn.RemoteAddr())
				lconn.Close()
			}
			// Close any spurious extra connections from the listener. (This is
			// possible if there are, for example, stray Dial calls from other tests.)
			for extraConn := range acceptc {
				t.Logf("spurious extra connection from %s", extraConn.RemoteAddr())
				extraConn.Close()
			}
			if ok {
				break
			}

			t.Logf("with timeout %v, DialWithDialer returned before listener accepted any connections; retrying", timeout)
			timeout *= 2
		}
	})

	t.Run("write deadline", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping in short mode")
		}

		ln := newLocalListener(t)
		defer ln.Close()

		srvCh := make(chan *Conn, 1)

		go func() {
			sconn, err := ln.Accept()
			if err != nil {
				srvCh <- nil
				return
			}
			srv := Server(sconn, serverCtx)
			if err := srv.Handshake(); err != nil {
				srvCh <- nil
				return
			}
			srvCh <- srv
		}()

		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		srv := <-srvCh
		if srv == nil {
			t.Error(err)
		}

		// Make sure the client/server is setup correctly and is able to do a typical Write/Read
		buf := make([]byte, 6)
		if _, err := srv.Write([]byte("foobar")); err != nil {
			t.Errorf("Write err: %v", err)
		}
		if n, err := conn.Read(buf); n != 6 || err != nil || string(buf) != "foobar" {
			t.Errorf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
		}

		// Set a deadline which should cause Write to timeout
		if err = srv.SetDeadline(time.Now()); err != nil {
			t.Fatalf("SetDeadline(time.Now()) err: %v", err)
		}
		if _, err = srv.Write([]byte("should fail")); err == nil {
			t.Fatal("Write should have timed out")
		}

		// Clear deadline and make sure it still times out
		if err = srv.SetDeadline(time.Time{}); err != nil {
			t.Fatalf("SetDeadline(time.Time{}) err: %v", err)
		}
		if _, err = srv.Write([]byte("This connection is permanently broken")); err == nil {
			t.Fatal("Write which previously failed should still time out")
		}

		// Verify the error
		if !isTimeoutError(err) {
			t.Error("Write timed out but did not classify the error as a Timeout")
		}
	})

	t.Run("test dialer", func(t *testing.T) {
		ln := newLocalListener(t)
		defer ln.Close()

		unblockServer := make(chan struct{}) // close-only
		defer close(unblockServer)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			<-unblockServer
		}()

		cfg, _ := NewClientConfig()
		cfg.PrivateKey = clientKey
		cfg.ServerPub = serverPub

		d := Dialer{Config: cfg}
		_, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
		assert.NoError(t, err)
	})

	t.Run("succesful", func(t *testing.T) {
		clientConfig, _ := NewClientConfig()
		clientConfig.PrivateKey = clientKey
		clientConfig.ServerPub = serverPub

		serverCtx, _ := NewServerContext()
		serverCtx.PrivateKey = serverKey
		defer serverCtx.Close()

		ln, err := Listen("tcp", ":0", serverCtx)
		require.NoError(t, err)
		defer ln.Close()

		ping := []byte("hello server!")
		pong := []byte("hello client!")
		go func() {
			sconn, err := ln.Accept()
			if err != nil {
				return
			}

			if err = sconn.(*Conn).Handshake(); err != nil {
				return
			}

			buf := make([]byte, 128)
			n, err := sconn.Read(buf)
			require.NoError(t, err)
			assert.Equal(t, ping, buf[:n])

			_, err = sconn.Write(pong)
			require.NoError(t, err)
		}()
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		require.NoError(t, err)
		defer conn.Close()

		_, err = conn.Write(ping)
		require.NoError(t, err)
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, pong, buf[:n])

		inR, inW, outR, outW := conn.Stat()
		t.Logf("inR: %d, inW: %d, outR: %d, outW: %d", inR, inW, outR, outW)
	})
}

func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
