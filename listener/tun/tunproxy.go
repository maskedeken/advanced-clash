package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	adapters "github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/log"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tunAdapter is the wraper of Device
type tunAdapter struct {
	Device
	ipstack    *stack.Stack
	udpInbound chan<- *inbound.PacketAdapter
}

// NewTun creates Tun Device
func NewTun(deviceName string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (Device, error) {

	if deviceName == "" {
		return nil, errors.New("empty device")
	}

	var err error

	tundev, err := Open(deviceName, 0)
	if err != nil {
		return nil, err
	}

	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	nicID := tcpip.NICID(ipstack.UniqueID())

	tl := &tunAdapter{
		Device:     tundev,
		ipstack:    ipstack,
		udpInbound: udpIn,
	}

	if err := ipstack.CreateNIC(nicID, tl.Device); err != nil {
		return nil, fmt.Errorf("fail to create NIC in ipstack: %v", err)
	}

	ipstack.SetPromiscuousMode(nicID, true) // Accept all the traffice from this NIC
	ipstack.SetSpoofing(nicID, true)        // Otherwise our TCP connection can not find the route backward

	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	// TCP handler
	// maximum number of half-open tcp connection set to 1024
	tcpFwd := tcp.NewForwarder(ipstack, 0, 2048, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Warnln("Can't create TCP Endpoint in ipstack: %v", err)
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)

		// if the endpoint is not in connected state, conn.RemoteAddr() will return nil
		// this protection may be not enough, but will help us debug the panic
		if conn.RemoteAddr() == nil {
			log.Warnln("TCP endpoint is not connected, current state: %v", tcp.EndpointState(ep.State()))
			conn.Close()
			return
		}

		target := getAddr(ep.Info().(*stack.TransportEndpointInfo).ID)
		tcpIn <- adapters.NewSocket(target, conn, C.TUN)

	})
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP handler
	ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, tl.udpHandlePacket)

	log.Infoln("Tun adapter have interface name: %s", tundev.Name())
	return tl, nil

}

func (t *tunAdapter) udpHandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// ref: gvisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
	hdr := header.UDP(pkt.TransportHeader().View().AsSlice())
	if int(hdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		// Malformed packet.
		t.ipstack.Stats().UDP.MalformedPacketsReceived.Increment()
		return true
	}

	target := getAddr(id)

	packet := &fakeConn{
		id:      id,
		pkt:     pkt,
		s:       t.ipstack,
		payload: pkt.Data().AsRange().ToSlice(),
	}
	t.udpInbound <- adapters.NewPacket(target, packet, C.TUN)

	return true
}

func getAddr(id stack.TransportEndpointID) socks5.Addr {
	ipv4 := id.LocalAddress.To4()

	// get the big-endian binary represent of port
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, id.LocalPort)

	if ipv4 != "" {
		addr := make([]byte, 1+net.IPv4len+2)
		addr[0] = socks5.AtypIPv4
		copy(addr[1:1+net.IPv4len], []byte(ipv4))
		addr[1+net.IPv4len], addr[1+net.IPv4len+1] = port[0], port[1]
		return addr
	} else {
		addr := make([]byte, 1+net.IPv6len+2)
		addr[0] = socks5.AtypIPv6
		copy(addr[1:1+net.IPv6len], []byte(id.LocalAddress))
		addr[1+net.IPv6len], addr[1+net.IPv6len+1] = port[0], port[1]
		return addr
	}

}
