// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package handlers

import (
	"encoding/binary"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
	"net"
)

func init() {
	RegisterHandler(Enums.PACKET_PACKED_CONTROL_BLOCKS, handlePackedControlBlocks)
}

func handlePackedControlBlocks(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	payload := packet.Payload
	const blockSize = 7

	for i := 0; i <= len(payload)-blockSize; i += blockSize {
		pType := payload[i]
		streamID := binary.BigEndian.Uint16(payload[i+1 : i+3])
		seqNum := binary.BigEndian.Uint16(payload[i+3 : i+5])
		fragID := payload[i+5]
		totalFrag := payload[i+6]

		innerPacket := VpnProto.Packet{
			SessionID:       packet.SessionID,
			PacketType:      pType,
			SessionCookie:   packet.SessionCookie,
			HasStreamID:     true,
			StreamID:        streamID,
			HasSequenceNum:  true,
			SequenceNum:     seqNum,
			HasFragmentInfo: true,
			FragmentID:      fragID,
			TotalFragments:  totalFrag,
		}

		// Recursively dispatch each inner control signal to its appropriate handler.
		if err := Dispatch(c, innerPacket, addr); err != nil {
			c.Log().Warnf("Error dispatching packed block (Type %d, Stream %d): %v", pType, streamID, err)
		}
	}

	return nil
}
