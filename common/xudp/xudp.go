package xudp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

// Addr types
const (
	AtypIPv4 byte = 1
	AtypIPv6 byte = 3
)

func NewXUDPConn(c net.Conn, addr *net.UDPAddr) *XUDPConn {
	return &XUDPConn{Conn: c,
		rAddr: addr,
	}
}

type XUDPConn struct {
	net.Conn
	rAddr  *net.UDPAddr
	remain int
	keep   bool
}

func (c *XUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	length := len(b)
	if length == 0 {
		return 0, nil
	}

	buffer := pool.GetBuffer()
	defer pool.PutBuffer(buffer)

	buffer.Write([]byte{0, 0, 0, 0})
	if !c.keep {
		buffer.WriteByte(1) // New
		buffer.WriteByte(1) // Opt
		buffer.WriteByte(2) // UDP
		writeAddressPort(buffer, c.rAddr)
		c.keep = true
	} else {
		buffer.WriteByte(2) // Keep
		buffer.WriteByte(1)
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			buffer.WriteByte(2)
			writeAddressPort(buffer, udpAddr)
		}
	}

	l := buffer.Len() - 2
	buffer.WriteByte(byte(length >> 8))
	buffer.WriteByte(byte(length))
	buffer.Write(b)
	eb := buffer.Bytes()
	eb[0] = byte(l >> 8)
	eb[1] = byte(l)

	_, err := c.Conn.Write(eb)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *XUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
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

	var headerLength uint16
	var packetLength uint16
	var err error
	var udpAddr *net.UDPAddr
	buffer := pool.GetBuffer()
	defer pool.PutBuffer(buffer)

	for {
		if err = binary.Read(c.Conn, binary.BigEndian, &headerLength); err != nil {
			return 0, nil, err
		}

		buffer.Reset()
		if _, err = io.CopyN(buffer, c.Conn, int64(headerLength)); err != nil {
			return 0, nil, err
		}

		header := buffer.Bytes()
		discard := false
		switch header[2] {
		case 2:
			if headerLength > 4 {
				udpAddr, err = readAddressPort(header[5:])
				if err != nil {
					return 0, nil, err
				}
			}
		case 4:
			discard = true
		default:
			return 0, nil, io.EOF
		}

		if header[3] == 1 {
			if err = binary.Read(c.Conn, binary.BigEndian, &packetLength); err != nil {
				return 0, nil, err
			}

			if packetLength > 0 {
				if discard {
					_, err = io.CopyN(ioutil.Discard, c.Conn, int64(packetLength)) // just discard
					if err != nil {
						return 0, nil, err
					}
				}

				remain := int(packetLength)
				n, err := c.Conn.Read(b[:length])
				remain -= n
				if remain > 0 {
					c.remain = remain
					c.rAddr = udpAddr
				}

				return n, udpAddr, err
			}
		}
	}
}

func writeAddressPort(writer io.Writer, udpAddr *net.UDPAddr) {
	port := udpAddr.Port
	writer.Write([]byte{byte(port >> 8), byte(port)})

	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		writer.Write([]byte{AtypIPv4})
		writer.Write(ip4)
	} else {
		writer.Write([]byte{AtypIPv6})
		writer.Write(udpAddr.IP.To16())
	}
}

func readAddressPort(p []byte) (*net.UDPAddr, error) {
	l := len(p)
	if l < 3 {
		return nil, nil
	}

	var ip net.IP
	switch p[2] {
	case AtypIPv4:
		if l < 3+net.IPv4len {
			return nil, errors.New("invalid ipv4 address")
		}

		ip = net.IP(p[3 : 3+net.IPv4len])
	case AtypIPv6:
		if l < 3+net.IPv6len {
			return nil, errors.New("invalid ipv6 address")
		}

		ip = net.IP(p[3 : 3+net.IPv6len])
	default:
		return nil, fmt.Errorf("unknown address type: %x", p[2])
	}

	port := int(p[0])<<8 | int(p[1])
	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}, nil
}
