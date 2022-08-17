package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	adapters "github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
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
	udpFwd := udp.NewForwarder(ipstack, func(r *udp.ForwarderRequest) {
		var (
			wq waiter.Queue
			id = r.ID()
		)
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Warnln("cannot create UDP endpoint: %s", err)
			return
		}

		target := getAddr(id)
		udpConn := gonet.NewUDPConn(ipstack, &wq, ep)

		go func() {
			for {
				buf := pool.Get(pool.UDPBufferSize)

				n, addr, err := udpConn.ReadFrom(buf)
				if err != nil {
					_ = pool.Put(buf)
					break
				}

				payload := buf[:n]
				packet := &packet{
					pc:      udpConn,
					rAddr:   addr,
					payload: payload,
				}

				select {
				case udpIn <- inbound.NewPacket(target, packet, C.TUN):
				default:
				}
			}
		}()
	})
	ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	log.Infoln("Tun adapter have interface name: %s", tundev.Name())
	return tl, nil

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

type packet struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload []byte
}

func (c *packet) Data() []byte {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, _ net.Addr) (n int, err error) {
	return c.pc.WriteTo(b, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	_ = pool.Put(c.payload)
}
