package rules

import (
	"github.com/Dreamacro/clash/component/ipset"
	C "github.com/Dreamacro/clash/constant"
)

type IPSET struct {
	binding     *ipset.IPSetBinding
	adapter     string
	noResolveIP bool
}

func (i *IPSET) RuleType() C.RuleType {
	return C.IPSET
}

func (i *IPSET) Match(metadata *C.Metadata) bool {
	ip := metadata.DstIP
	if ip == nil {
		return false
	}

	return i.binding.Test(ip)
}

func (i *IPSET) Adapter() string {
	return i.adapter
}

func (i *IPSET) Payload() string {
	return i.binding.SetName
}

func (i *IPSET) ShouldResolveIP() bool {
	return !i.noResolveIP
}

func (i *IPSET) ShouldFindProcess() bool {
	return false
}

func NewIPSET(setName string, adapter string, noResolveIP bool) *IPSET {
	binding := &ipset.IPSetBinding{SetName: setName}
	return &IPSET{
		binding:     binding,
		adapter:     adapter,
		noResolveIP: noResolveIP,
	}
}
