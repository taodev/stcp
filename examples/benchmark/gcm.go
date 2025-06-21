package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/taodev/stcp"
)

type mockBuffer struct {
	buf  []byte
	wpos int
	rpos int
}

func (m *mockBuffer) Read(b []byte) (n int, err error) {
	if m.rpos >= m.wpos {
		return 0, io.EOF
	}

	n = copy(b, m.buf[m.rpos:m.wpos])
	m.rpos += n
	return
}

func (m *mockBuffer) Write(b []byte) (n int, err error) {
	if m.wpos >= len(m.buf) {
		return 0, io.EOF
	}

	n = copy(m.buf[m.wpos:], b)
	m.wpos += n
	return
}

func (m *mockBuffer) Reset() {
	m.wpos = 0
	m.rpos = 0
}

func NewMockBuffer(buf []byte) *mockBuffer {
	return &mockBuffer{
		buf: buf,
	}
}

func benchmarkRead(name string, r io.Reader, buf *mockBuffer) {
	now := time.Now()

	// 读取 1GB 原始数据
	rdata := make([]byte, 1024*1024)
	for i := 0; i < 256; i++ {
		_, err := io.ReadFull(r, rdata)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// 输出结果
	fmt.Printf("%-16s %-8s %-8s %-8.2fMB %v\n", name, "Read", "1GB", float64(buf.rpos)/(1024*1024), time.Since(now))
}

func benchmarkWrite(name string, w io.Writer, data []byte, buf *mockBuffer) {
	now := time.Now()

	// 写入 1GB 原始数据
	for i := 0; i < 256; i++ {
		_, err := w.Write(data)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// 输出结果
	fmt.Printf("%-16s %-8s %-8s %-8.2fMB %v\n", name, "Write", "1GB", float64(buf.wpos)/(1024*1024), time.Since(now))
}

func benchmarkCopy() {
	fmt.Println("benchmarkCopy")

	// 创建 1MB 测试数据
	data := make([]byte, 1024*1024)
	io.ReadFull(rand.Reader, data)

	now := time.Now()

	// 读取 1GB 原始数据
	wdata := make([]byte, 1024*1024)
	for i := 0; i < 1024; i++ {
		copy(wdata, data)
	}

	// 输出结果
	fmt.Printf("Copy 1GB data in %v\n", time.Since(now))
}

func testGCM() {
	// 创建 1MB 测试数据
	// data := make([]byte, 1024*1024)
	// io.ReadFull(rand.Reader, data)

	block := make([]byte, 1024)
	io.ReadFull(rand.Reader, block)
	data := bytes.Repeat(block, 1024)

	dataCacheLen := 1024 * 1024 * 512
	dataCache := make([]byte, dataCacheLen)
	buffer := NewMockBuffer(dataCache)

	var (
		w io.Writer
		r io.Reader
	)

	benchmarkCopy()

	// snappy
	{
		buffer.Reset()

		w = stcp.NewSnappyWriter(buffer)
		benchmarkWrite("snappy", w, data, buffer)

		r = stcp.NewSnappyReader(buffer)
		benchmarkRead("snappy", r, buffer)
	}

	// aesgcm
	{
		key := make([]byte, 32)
		io.ReadFull(rand.Reader, key)
		buffer.Reset()

		w = stcp.NewGCMWriter(buffer, key)
		benchmarkWrite("aesgcm", w, data, buffer)

		r = stcp.NewGCMReader(buffer, key)
		benchmarkRead("aesgcm", r, buffer)
	}

	// aescfb
	{
		key := make([]byte, 32)
		io.ReadFull(rand.Reader, key)
		buffer.Reset()

		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Println(err)
			return
		}

		iv := make([]byte, aes.BlockSize)
		io.ReadFull(rand.Reader, iv)

		w = cipher.StreamWriter{
			S: cipher.NewCFBEncrypter(block, iv),
			W: buffer,
		}
		benchmarkWrite("aescfb", w, data, buffer)

		r = cipher.StreamReader{
			S: cipher.NewCFBDecrypter(block, iv),
			R: buffer,
		}
		benchmarkRead("aescfb", r, buffer)
	}

	// snappy + aesgcm
	{
		key := make([]byte, 32)
		io.ReadFull(rand.Reader, key)
		buffer.Reset()

		w = stcp.NewGCMWriter(buffer, key)
		w = stcp.NewSnappyWriter(w)
		benchmarkWrite("snappy+aesgcm", w, data, buffer)

		r = stcp.NewGCMReader(buffer, key)
		r = stcp.NewSnappyReader(r)
		benchmarkRead("snappy+aesgcm", r, buffer)
	}

	// snappy + aescfb
	{
		key := make([]byte, 32)
		io.ReadFull(rand.Reader, key)
		buffer.Reset()

		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Println(err)
			return
		}

		iv := make([]byte, aes.BlockSize)
		io.ReadFull(rand.Reader, iv)

		w = cipher.StreamWriter{
			S: cipher.NewCFBEncrypter(block, iv),
			W: buffer,
		}
		w = stcp.NewSnappyWriter(w)
		benchmarkWrite("snappy+aescfb", w, data, buffer)

		r = cipher.StreamReader{
			S: cipher.NewCFBDecrypter(block, iv),
			R: buffer,
		}
		r = stcp.NewSnappyReader(r)
		benchmarkRead("snappy+aescfb", r, buffer)
	}

	// aesgcm + snappy
	{
		key := make([]byte, 32)
		io.ReadFull(rand.Reader, key)

		buffer.Reset()

		w = stcp.NewSnappyWriter(buffer)
		w = stcp.NewGCMWriter(w, key)
		benchmarkWrite("aesgcm+snappy", w, data, buffer)

		r = stcp.NewSnappyReader(buffer)
		r = stcp.NewGCMReader(r, key)
		benchmarkRead("aesgcm+snappy", r, buffer)
	}
}
