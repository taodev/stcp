package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/taodev/stcp"
)

func main() {
	testGCM()

	benchmarkSTCP()
}

func benchmarkSTCP() {
	// runtime.GOMAXPROCS(runtime.NumCPU())
	server, err := stcp.Listen("tcp", "127.0.0.1:0", &stcp.Config{
		Password: "testpassword",
	})
	if err != nil {
		panic(err)
	}

	message := make([]byte, 7000)
	io.ReadFull(rand.Reader, message)

	go func() {
		conn, err := server.Accept()
		if err != nil {
			panic(err)
		}
		if err = conn.(*stcp.Conn).Handshake(); err != nil {
			conn.Close()
			panic(err)
		}

		rbuf := make([]byte, len(message))
		for {
			n, err := io.ReadFull(conn, rbuf)
			if err != nil {
				break
			}

			if n != len(rbuf) {
				panic("read error")
			}

			if !bytes.Equal(rbuf, message) {
				panic("read error")
			}
		}
	}()

	client, err := stcp.Dial("tcp", server.Addr().String(), &stcp.Config{
		Password: "testpassword",
	})
	if err != nil {
		panic(err)
	}

	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		var inR, inW, outR, outW int64
		for {
			<-t.C
			r1, w1, r2, w2 := client.Stat()
			fmt.Printf("inR: %dMB, inW: %dMB, outR: %dMB, outW: %dMB\n",
				(r1-inR)/(1024*1024), (w1-inW)/(1024*1024), (r2-outR)/(1024*1024), (w2-outW)/(1024*1024),
			)
			inR = r1
			inW = w1
			outR = r2
			outW = w2
		}
	}()

	// now := time.Now()
	for {
		_, err := client.Write(message)
		if err != nil {
			panic(err)
		}
	}

	// fmt.Println("benchmarkSTCP done")
	// inR, inW, outR, outW := client.Stat()
	// fmt.Printf("inR: %dMB, inW: %dMB, outR: %dMB, outW: %dMB\n",
	// 	inR/1024*1024, inW/1024*1024, outR/1024*1024, outW/1024*1024)
	// fmt.Printf("time: %dms\n", time.Since(now).Milliseconds())

	// client.Close()
	// server.Close()
}
