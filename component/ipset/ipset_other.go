// +build !linux

package ipset

import (
	"net"

	"github.com/Dreamacro/clash/log"
)

func (i *IPSetBinding) Test(entry net.IP) bool {
	log.Errorln("IPSet is not supported")
	return false
}
