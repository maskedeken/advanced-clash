package vless

import (
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"sync"

	"github.com/Dreamacro/clash/common/pool"
)

type vlessConn struct {
	net.Conn
	received bool
}

func NewVlessConn(c net.Conn) net.Conn {
	return &vlessConn{
		Conn: c,
	}
}

func (vc *vlessConn) Read(b []byte) (int, error) {
	if !vc.received {
		if err := vc.recvResponse(); err != nil {
			return 0, err
		}
		vc.received = true
	}

	return vc.Conn.Read(b)
}

func (vc *vlessConn) recvResponse() error {
	var err error
	buf := make([]byte, 1)
	_, err = io.ReadFull(vc.Conn, buf)
	if err != nil {
		return err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	_, err = io.ReadFull(vc.Conn, buf)
	if err != nil {
		return err
	}

	length := int64(buf[0])
	if length != 0 { // addon data length > 0
		io.CopyN(ioutil.Discard, vc.Conn, length) // just discard
	}

	return nil
}

func NewVlessPacketConn(c net.Conn, addr net.Addr) net.PacketConn {
	return &vlessPacketConn{Conn: c,
		rAddr: addr,
	}
}

type vlessPacketConn struct {
	net.Conn
	rAddr  net.Addr
	remain int
	mux    sync.Mutex
}

func (c *vlessPacketConn) writePacket(b []byte, addr net.Addr) (int, error) {
	length := len(b)
	if length == 0 {
		return 0, nil
	}

	buffer := pool.GetBuffer()
	defer pool.PutBuffer(buffer)

	buffer.WriteByte(byte(length >> 8))
	buffer.WriteByte(byte(length))
	buffer.Write(b)
	n, err := c.Conn.Write(buffer.Bytes())
	if n > 2 {
		return n - 2, err
	}

	return 0, err
}

func (c *vlessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) <= maxLength {
		return c.writePacket(b, addr)
	}

	offset := 0
	total := len(b)
	for offset < total {
		cursor := offset + maxLength
		if cursor > total {
			cursor = total
		}

		n, err := c.writePacket(b[offset:cursor], addr)
		if err != nil {
			return offset + n, err
		}

		offset = cursor
	}

	return total, nil
}

func (c *vlessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	length := len(b)
	if c.remain > 0 {
		if c.remain < length {
			length = c.remain
		}

		n, err := c.Conn.Read(b[:length])
		if err != nil {
			return 0, nil, err
		}

		c.remain -= n
		return n, c.rAddr, nil
	}

	var packetLength uint16
	if err := binary.Read(c.Conn, binary.BigEndian, &packetLength); err != nil {
		return 0, nil, err
	}

	remain := int(packetLength)
	n, err := c.Conn.Read(b[:length])
	remain -= n
	if remain > 0 {
		c.remain = remain
	}
	return n, c.rAddr, err
}
