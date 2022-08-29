package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/Dreamacro/clash/common/xudp"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/vless"
)

type Vless struct {
	*Base
	client *vless.Client
	option *VlessOption
}

type VlessOption struct {
	Name           string    `proxy:"name"`
	Server         string    `proxy:"server"`
	Port           int       `proxy:"port"`
	UUID           string    `proxy:"uuid"`
	UDP            bool      `proxy:"udp,omitempty"`
	XUDP           bool      `proxy:"xudp,omitempty"`
	ALPN           []string  `proxy:"alpn,omitempty"`
	Network        string    `proxy:"network,omitempty"`
	WSOpts         WSOptions `proxy:"ws-opts,omitempty"`
	SkipCertVerify bool      `proxy:"skip-cert-verify,omitempty"`
	ServerName     string    `proxy:"servername,omitempty"`
}

func (v *Vless) plainStream(c net.Conn) (net.Conn, error) {
	if v.option.Network == "ws" {
		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &vless.WebsocketOption{
			Host: host,
			Port: port,
			Path: v.option.WSOpts.Path,
		}

		if len(v.option.WSOpts.Headers) != 0 {
			header := http.Header{}
			for key, value := range v.option.WSOpts.Headers {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		return v.client.StreamWebsocketConn(c, wsOpts)
	}

	return v.client.StreamConn(c)
}

func (v *Vless) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	c, err = v.plainStream(c)

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", v.addr, err)
	}

	err = v.client.WriteHeader(c, parseVmessAddr(metadata))
	if err != nil {
		return nil, err
	}

	return vless.NewVlessConn(c), nil
}

func (v *Vless) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = v.StreamConn(c, metadata)
	return NewConn(c, v), err
}

func (v *Vless) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	// vless use stream-oriented udp, so clash needs a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = v.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	var packetConn net.PacketConn
	if v.option.XUDP {
		packetConn = xudp.NewXUDPConn(c, metadata.UDPAddr())
	} else {
		packetConn = vless.NewVlessPacketConn(c, metadata.UDPAddr())
	}
	return newPacketConn(packetConn, v), nil
}

func NewVless(option VlessOption) (v *Vless, err error) {
	host, port := option.Server, strconv.Itoa(option.Port)

	vOption := &vless.Option{
		UUID:           option.UUID,
		ALPN:           option.ALPN,
		ServerName:     option.Server,
		SkipCertVerify: option.SkipCertVerify,
		XUDP:           option.XUDP,
	}

	if option.ServerName != "" {
		vOption.ServerName = option.ServerName
	}

	v = &Vless{
		Base: &Base{
			name: option.Name,
			addr: net.JoinHostPort(host, port),
			tp:   C.Vless,
			udp:  option.UDP,
		},
		option: &option,
	}
	v.client, err = vless.NewClient(vOption)
	return
}
