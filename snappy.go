package stcp

import (
	"io"

	"github.com/golang/snappy"
)

type SnappyWriter struct {
	*snappy.Writer
}

func NewSnappyWriter(w io.Writer) *SnappyWriter {
	return &SnappyWriter{
		Writer: snappy.NewBufferedWriter(w),
	}
}

func (w *SnappyWriter) Write(p []byte) (n int, err error) {
	if n, err = w.Writer.Write(p); err != nil {
		return
	}
	err = w.Writer.Flush()
	return
}

type SnappyReader struct {
	*snappy.Reader
}

func NewSnappyReader(r io.Reader) *SnappyReader {
	return &SnappyReader{
		Reader: snappy.NewReader(r),
	}
}
