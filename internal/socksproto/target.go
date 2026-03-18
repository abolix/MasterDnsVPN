// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package socksproto

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	AddressTypeIPv4   = 0x01
	AddressTypeDomain = 0x03
	AddressTypeIPv6   = 0x04
)

var (
	ErrTargetTooShort         = errors.New("socks target payload too short")
	ErrUnsupportedAddressType = errors.New("unsupported socks address type")
	ErrInvalidDomainLength    = errors.New("invalid socks domain length")
)

type Target struct {
	AddressType uint8
	Host        string
	Port        uint16
}

func ParseTargetPayload(payload []byte) (Target, error) {
	if len(payload) < 3 {
		return Target{}, ErrTargetTooShort
	}

	target := Target{AddressType: payload[0]}
	offset := 1

	switch payload[0] {
	case AddressTypeIPv4:
		if len(payload) < offset+4+2 {
			return Target{}, ErrTargetTooShort
		}
		target.Host = net.IP(payload[offset : offset+4]).String()
		offset += 4
	case AddressTypeDomain:
		if len(payload) < offset+1 {
			return Target{}, ErrTargetTooShort
		}
		domainLength := int(payload[offset])
		offset++
		if domainLength < 1 || len(payload) < offset+domainLength+2 {
			return Target{}, ErrInvalidDomainLength
		}
		target.Host = string(payload[offset : offset+domainLength])
		offset += domainLength
	case AddressTypeIPv6:
		if len(payload) < offset+16+2 {
			return Target{}, ErrTargetTooShort
		}
		target.Host = net.IP(payload[offset : offset+16]).String()
		offset += 16
	default:
		return Target{}, ErrUnsupportedAddressType
	}

	target.Port = binary.BigEndian.Uint16(payload[offset : offset+2])
	return target, nil
}
