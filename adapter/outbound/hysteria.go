package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/lucas-clemente/quic-go"

	"github.com/HyNetwork/hysteria/pkg/core"
	"github.com/HyNetwork/hysteria/pkg/pmtud"
	"github.com/HyNetwork/hysteria/pkg/transport/pktconns"
)

const (
	mbpsToBps   = 125000
	minSpeedBPS = 16384

	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
	DefaultMaxIncomingStreams      = 1024

	DefaultALPN = "hysteria"

	KeepAlivePeriod = 10 * time.Second
)

var rateStringRegexp = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

type Hysteria struct {
	*Base

	client *core.Client
}

func (h *Hysteria) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	hdc := hyDialerWithContext{
		ctx: ctx,
		hyDialer: func() (net.PacketConn, error) {
			return dialer.ListenPacket(ctx, "udp", "", h.Base.DialOptions(opts...)...)
		},
	}
	tcpConn, err := h.client.DialTCP(metadata.RemoteAddress(), &hdc)
	if err != nil {
		return nil, err
	}

	return NewConn(tcpConn, h), nil
}

func (h *Hysteria) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	hdc := hyDialerWithContext{
		ctx: ctx,
		hyDialer: func() (net.PacketConn, error) {
			return dialer.ListenPacket(ctx, "udp", "", h.Base.DialOptions(opts...)...)
		},
	}
	udpConn, err := h.client.DialUDP(&hdc)
	if err != nil {
		return nil, err
	}
	return newPacketConn(&hyPacketConn{udpConn}, h), nil
}

type HysteriaOption struct {
	BasicOption
	Name                string `proxy:"name"`
	Server              string `proxy:"server"`
	Port                int    `proxy:"port"`
	Protocol            string `proxy:"protocol,omitempty"`
	Up                  string `proxy:"up"`
	Down                string `proxy:"down"`
	AuthString          string `proxy:"auth_str,omitempty"`
	Obfs                string `proxy:"obfs,omitempty"`
	SNI                 string `proxy:"sni,omitempty"`
	SkipCertVerify      bool   `proxy:"skip-cert-verify,omitempty"`
	ALPN                string `proxy:"alpn,omitempty"`
	ReceiveWindowConn   int    `proxy:"recv_window_conn,omitempty"`
	ReceiveWindow       int    `proxy:"recv_window,omitempty"`
	DisableMTUDiscovery bool   `proxy:"disable_mtu_discovery,omitempty"`
}

func NewHysteria(option HysteriaOption) (*Hysteria, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: option.SkipCertVerify,
		MinVersion:         tls.VersionTLS13,
	}
	if len(option.ALPN) > 0 {
		tlsConfig.NextProtos = []string{option.ALPN}
	} else {
		tlsConfig.NextProtos = []string{DefaultALPN}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		KeepAlivePeriod:                KeepAlivePeriod,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}

	clientPacketConnFunc, err := getClientPacketConnFunc(option.Protocol, option.Obfs)
	if err != nil {
		return nil, err
	}

	if option.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnectionReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = DefaultConnectionReceiveWindow
	}
	if !quicConfig.DisablePathMTUDiscovery && pmtud.DisablePathMTUDiscovery {
		log.Infoln("hysteria: Path MTU Discovery is not yet supported on this platform")
	}

	up := stringToBps(option.Up)
	if up == 0 {
		return nil, fmt.Errorf("invaild upload speed: %s", option.Up)
	}

	down := stringToBps(option.Down)
	if down == 0 {
		return nil, fmt.Errorf("invaild download speed: %s", option.Down)
	}

	client, err := core.NewClient(
		addr, []byte(option.AuthString), tlsConfig, quicConfig, clientPacketConnFunc, up, down, func(err error) {
			log.Debugln("Connection to %s lost, reconnecting...", addr)
		})
	if err != nil {
		return nil, fmt.Errorf("hysteria %s create error: %w", addr, err)
	}

	return &Hysteria{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Hysteria,
			udp:   true,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		client: client,
	}, nil
}

func stringToBps(s string) uint64 {
	if s == "" {
		return 0
	}

	// when have not unit, use Mbps
	if v, err := strconv.Atoi(s); err == nil {
		return stringToBps(fmt.Sprintf("%d Mbps", v))
	}

	m := rateStringRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	var n uint64
	switch m[2] {
	case "K":
		n = 1 << 10
	case "M":
		n = 1 << 20
	case "G":
		n = 1 << 30
	case "T":
		n = 1 << 40
	default:
		n = 1
	}
	v, _ := strconv.ParseUint(m[1], 10, 64)
	n = v * n
	if m[3] == "b" {
		// Bits, need to convert to bytes
		n = n >> 3
	}
	return n
}

func getClientPacketConnFunc(protocol, obfsPassword string) (pktconns.ClientPacketConnFunc, error) {
	proto := strings.ToLower(protocol)
	switch proto {
	case "", "udp":
		return pktconns.NewClientUDPConnFunc(obfsPassword), nil
	case "wechat", "wechat-video":
		return pktconns.NewClientWeChatConnFunc(obfsPassword), nil
	default:
		return nil, fmt.Errorf("Unsupported protocol: %s", protocol)
	}
}

type hyPacketConn struct {
	core.HyUDPConn
}

func (c *hyPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	b, addrStr, err := c.HyUDPConn.ReadFrom()
	if err != nil {
		return
	}
	n = copy(p, b)
	addr = socks5.ParseAddr(addrStr).UDPAddr()
	return
}

func (c *hyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = c.HyUDPConn.WriteTo(p, socks5.ParseAddrToSocksAddr(addr).String())
	if err != nil {
		return
	}
	n = len(p)
	return
}

type hyDialerWithContext struct {
	hyDialer func() (net.PacketConn, error)
	ctx      context.Context
}

func (h *hyDialerWithContext) ListenPacket() (net.PacketConn, error) {
	return h.hyDialer()
}

func (h *hyDialerWithContext) Context() context.Context {
	return h.ctx
}
