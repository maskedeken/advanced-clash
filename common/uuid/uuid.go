package uuid

import (
	"crypto/sha1"

	"github.com/gofrs/uuid"
)

// ParseString converts a UUID in string form to object.
func ParseString(str string) (uuid.UUID, error) {
	text := []byte(str)
	if l := len(text); l > 0 && l < 31 {
		var uid uuid.UUID
		h := sha1.New()
		h.Write(uid[:])
		h.Write(text)
		u := h.Sum(nil)[:16]
		u[6] = (u[6] & 0x0f) | (5 << 4)
		u[8] = (u[8]&(0xff>>2) | (0x02 << 6))
		return uuid.FromBytes(u)
	}

	return uuid.FromString(str)
}
