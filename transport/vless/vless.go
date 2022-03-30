package vless

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"

	"github.com/Dreamacro/clash/common/pool"
	u "github.com/Dreamacro/clash/common/uuid"
	"github.com/Dreamacro/clash/transport/vmess"
	"github.com/gofrs/uuid"
)

const (
	Version byte = 0 // protocol version. preview version is 0

	// max packet length
	maxLength = 2046
)

var (
	defaultALPN = []string{"h2", "http/1.1"}
)

type Option struct {
	UUID           string
	ALPN           []string
	ServerName     string
	SkipCertVerify bool
}

type WebsocketOption struct {
	Host    string
	Port    string
	Path    string
	Headers http.Header
}

// Client is vless connection generator
type Client struct {
	uuid   *uuid.UUID
	option *Option
}

func (c *Client) StreamConn(conn net.Conn) (net.Conn, error) {
	alpn := defaultALPN
	if len(c.option.ALPN) != 0 {
		alpn = c.option.ALPN
	}

	tlsConfig := &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.option.SkipCertVerify,
		ServerName:         c.option.ServerName,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (c *Client) StreamWebsocketConn(conn net.Conn, wsOptions *WebsocketOption) (net.Conn, error) {
	tlsConfig := &tls.Config{
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.option.SkipCertVerify,
		ServerName:         c.option.ServerName,
	}

	return vmess.StreamWebsocketConn(conn, &vmess.WebsocketConfig{
		Host:      wsOptions.Host,
		Port:      wsOptions.Port,
		Path:      wsOptions.Path,
		Headers:   wsOptions.Headers,
		TLS:       true,
		TLSConfig: tlsConfig,
	})
}

// WriteHeader sends VLESS header
func (c *Client) WriteHeader(w io.Writer, dst *vmess.DstAddr) error {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	buf.WriteByte(Version)    // protocol version
	buf.Write(c.uuid.Bytes()) // 16 bytes of uuid

	// addons
	buf.WriteByte(0)

	command := vmess.CommandTCP
	if dst.UDP {
		command = vmess.CommandUDP
	}
	buf.WriteByte(command) // command

	// Port AddrType Addr
	binary.Write(buf, binary.BigEndian, uint16(dst.Port))
	buf.WriteByte(dst.AddrType)
	buf.Write(dst.Addr)

	_, err := w.Write(buf.Bytes())
	return err
}

// NewClient return Client instance
func NewClient(option *Option) (*Client, error) {
	uid, err := u.ParseString(option.UUID)
	if err != nil {
		return nil, err
	}

	return &Client{
		uuid:   &uid,
		option: option,
	}, nil
}
