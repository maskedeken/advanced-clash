package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	D "github.com/miekg/dns"
)

type dnsCryptClient struct {
	addr       string
	iface      string
	client     *dnscrypt.Client       // DNSCrypt client properties
	serverInfo *dnscrypt.ResolverInfo // DNSCrypt resolver info

	sync.RWMutex // protects DNSCrypt client
}

func newDnsCryptClient(addr, iface string) *dnsCryptClient {
	return &dnsCryptClient{
		addr:  addr,
		iface: iface,
	}
}

func (dc *dnsCryptClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	errChan := make(chan error, 1)
	replyChan := make(chan *D.Msg, 1)

	go func() {
		reply, err1 := dc.Exchange(m)
		if err1 != nil {
			errChan <- err1
			return
		}

		replyChan <- reply
	}()

	select {
	case msg = <-replyChan:
	case err = <-errChan:
	case <-ctx.Done():
		return nil, context.DeadlineExceeded
	}

	return
}

func (dc *dnsCryptClient) Exchange(m *D.Msg) (*D.Msg, error) {
	reply, err := dc.exchangeDNSCrypt(m)

	if os.IsTimeout(err) || err == io.EOF {
		// If request times out, it is possible that the server configuration has been changed.
		// It is safe to assume that the key was rotated (for instance, as it is described here: https://dnscrypt.pl/2017/02/26/how-key-rotation-is-automated/).
		// We should re-fetch the server certificate info so that the new requests were not failing.
		dc.Lock()
		dc.client = nil
		dc.serverInfo = nil
		dc.Unlock()

		// Retry the request one more time
		return dc.exchangeDNSCrypt(m)
	}

	return reply, err
}

// exchangeDNSCrypt attempts to send the DNS query and returns the response
func (dc *dnsCryptClient) exchangeDNSCrypt(m *D.Msg) (*D.Msg, error) {
	var client *dnscrypt.Client
	var resolverInfo *dnscrypt.ResolverInfo

	dc.RLock()
	client = dc.client
	resolverInfo = dc.serverInfo
	dc.RUnlock()

	now := uint32(time.Now().Unix())
	if client == nil || resolverInfo == nil || resolverInfo.ResolverCert.NotAfter < now {
		dc.Lock()

		// Using "udp" for DNSCrypt upstreams by default
		client = &dnscrypt.Client{
			Timeout: resolver.DefaultDNSTimeout,
			Dialer:  dc.dial,
		}

		ri, err := client.Dial(dc.addr)
		if err != nil {
			dc.Unlock()
			stamp, _ := dnsstamps.NewServerStampFromString(dc.addr)
			return nil, fmt.Errorf("failed to fetch certificate info from %s: %s", stamp.ServerAddrStr, err)
		}

		dc.client = client
		dc.serverInfo = ri
		resolverInfo = ri
		dc.Unlock()
	}

	reply, err := client.Exchange(m, resolverInfo)

	if reply != nil && reply.Truncated {
		log.Debugln("[DNSCrypt] Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		tcpClient := dnscrypt.Client{
			Timeout: resolver.DefaultDNSTimeout,
			Net:     "tcp",
			Dialer:  dc.dial,
		}
		reply, err = tcpClient.Exchange(m, resolverInfo)
	}

	if err == nil && reply != nil && reply.Id != m.Id {
		err = D.ErrId
	}

	return reply, err
}

func (dc *dnsCryptClient) dial(network, addr string) (net.Conn, error) {
	if strings.HasPrefix(network, "tcp") {
		network = "tcp"
	} else {
		network = "udp"
	}

	options := []dialer.Option{}
	if dc.iface != "" {
		options = append(options, dialer.WithInterface(dc.iface))
	}

	return dialer.DialContext(context.Background(), network, addr, options...)
}
