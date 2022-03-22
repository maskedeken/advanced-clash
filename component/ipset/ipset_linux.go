// +build linux

package ipset

import (
	"net"

	"github.com/Dreamacro/clash/log"
	S "github.com/digineo/go-ipset/v2"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Test is used to check whether the specified entry is in the set or not.
func (i *IPSetBinding) Test(entry net.IP) bool {
	conn, err := S.Dial(netfilter.ProtoUnspec, &netlink.Config{})
	if err != nil {
		log.Errorln("Error in testing ip: %s", err.Error())
		return false
	}
	defer conn.Close()
	err = conn.Test(i.SetName, S.EntryIP(entry))
	return err == nil
}
