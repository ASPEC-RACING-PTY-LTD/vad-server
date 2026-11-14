package inspect

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Clamd scans content with a ClamAV daemon (clamd) over its INSTREAM
// protocol. Addr is "tcp://host:3310" or "unix:///path/to/clamd.sock".
type Clamd struct {
	Addr    string
	MaxSize int64 // bigger files are not sent (clamd's StreamMaxLength)
}

// ErrTooLarge means the file is bigger than MaxSize and was not scanned.
var ErrTooLarge = errors.New("too large for the antivirus scan")

func (c Clamd) dial() (net.Conn, error) {
	network, addr, ok := strings.Cut(c.Addr, "://")
	if !ok {
		network, addr = "tcp", c.Addr
	}
	if network != "tcp" && network != "unix" {
		return nil, fmt.Errorf("clamd address %q: use tcp:// or unix://", c.Addr)
	}
	return net.DialTimeout(network, addr, 5*time.Second)
}

// Scan streams r (size bytes) to clamd. found is the signature name when
// clamd reports one.
func (c Clamd) Scan(r io.Reader, size int64) (found string, err error) {
	if c.MaxSize > 0 && size > c.MaxSize {
		return "", ErrTooLarge
	}
	conn, err := c.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10*time.Minute + time.Duration(size/(1<<20))*time.Second))
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", err
	}
	buf := make([]byte, 64<<10)
	var lenBuf [4]byte
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf[:], uint32(n))
			if _, err := conn.Write(lenBuf[:]); err != nil {
				return "", err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(conn).ReadString(0)
	if err != nil && reply == "" {
		return "", err
	}
	reply = strings.TrimPrefix(strings.TrimRight(reply, "\x00\n "), "stream: ")
	switch {
	case reply == "OK":
		return "", nil
	case strings.HasSuffix(reply, " FOUND"):
		return strings.TrimSuffix(reply, " FOUND"), nil
	}
	return "", fmt.Errorf("clamd: %s", reply)
}
