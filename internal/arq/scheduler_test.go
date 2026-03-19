// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package arq

import (
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestPackedControlBlockLimitUsesMtuAndCap(t *testing.T) {
	if got := ComputeClientPackedControlBlockLimit(200, 99); got != 14 {
		t.Fatalf("unexpected client pack limit: got=%d want=14", got)
	}
	if got := ComputeServerPackedControlBlockLimit(200, 99); got != 22 {
		t.Fatalf("unexpected server pack limit: got=%d want=22", got)
	}
	if got := ComputeClientPackedControlBlockLimit(10, 99); got != 1 {
		t.Fatalf("small mtu should clamp to 1, got=%d", got)
	}
	if got := ComputeServerPackedControlBlockLimit(4096, 20); got != 20 {
		t.Fatalf("user cap should still apply, got=%d", got)
	}
}

func TestSchedulerRejectsDuplicateDataAndQueuedResend(t *testing.T) {
	scheduler := NewScheduler(4)

	data := QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    7,
		SequenceNum: 11,
		Priority:    2,
	}
	if !scheduler.Enqueue(QueueTargetStream, data) {
		t.Fatal("expected first data enqueue to succeed")
	}
	if scheduler.Enqueue(QueueTargetStream, data) {
		t.Fatal("duplicate data packet should be rejected")
	}
	if scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_RESEND,
		StreamID:    7,
		SequenceNum: 11,
		Priority:    2,
	}) {
		t.Fatal("resend should be rejected while original data is still queued")
	}
}

func TestSchedulerPreservesRoundRobinForSamePriority(t *testing.T) {
	scheduler := NewScheduler(1)
	if !scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    1,
		SequenceNum: 1,
		Priority:    2,
	}) {
		t.Fatal("expected stream 1 enqueue to succeed")
	}
	if !scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    2,
		SequenceNum: 1,
		Priority:    2,
	}) {
		t.Fatal("expected stream 2 enqueue to succeed")
	}

	first, ok := scheduler.Dequeue()
	if !ok || first.Packet.StreamID != 1 {
		t.Fatalf("expected stream 1 first, got %+v ok=%v", first.Packet, ok)
	}

	second, ok := scheduler.Dequeue()
	if !ok || second.Packet.StreamID != 2 {
		t.Fatalf("expected stream 2 second, got %+v ok=%v", second.Packet, ok)
	}
}

func TestSchedulerRoundRobinBeatsCrossOwnerPriorityStarvation(t *testing.T) {
	scheduler := NewScheduler(1)
	if !scheduler.Enqueue(QueueTargetMain, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_FIN_ACK,
		StreamID:    0,
		SequenceNum: 1,
		Priority:    9,
	}) {
		t.Fatal("expected main owner enqueue to succeed")
	}
	if !scheduler.Enqueue(QueueTargetMain, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_RST_ACK,
		StreamID:    0,
		SequenceNum: 2,
		Priority:    9,
	}) {
		t.Fatal("expected second main owner enqueue to succeed")
	}
	if !scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    7,
		SequenceNum: 1,
		Priority:    20,
	}) {
		t.Fatal("expected stream owner enqueue to succeed")
	}

	first, ok := scheduler.Dequeue()
	if !ok || first.Packet.StreamID != 0 || first.Packet.PacketType != Enums.PACKET_STREAM_FIN_ACK {
		t.Fatalf("expected main owner first packet, got=%+v ok=%v", first.Packet, ok)
	}

	second, ok := scheduler.Dequeue()
	if !ok || second.Packet.StreamID != 7 || second.Packet.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected stream owner to get next turn despite lower priority, got=%+v ok=%v", second.Packet, ok)
	}

	third, ok := scheduler.Dequeue()
	if !ok || third.Packet.StreamID != 0 || third.Packet.PacketType != Enums.PACKET_STREAM_RST_ACK {
		t.Fatalf("expected main owner remaining packet last, got=%+v ok=%v", third.Packet, ok)
	}
}

func TestSchedulerPacksSamePriorityControlBlocksAcrossStreams(t *testing.T) {
	scheduler := NewScheduler(4)
	packets := []QueuedPacket{
		{PacketType: Enums.PACKET_STREAM_SYN_ACK, StreamID: 1, SequenceNum: 10, Priority: 3},
		{PacketType: Enums.PACKET_STREAM_FIN_ACK, StreamID: 1, SequenceNum: 11, Priority: 3},
		{PacketType: Enums.PACKET_STREAM_RST_ACK, StreamID: 2, SequenceNum: 20, Priority: 3},
		{PacketType: Enums.PACKET_SOCKS5_CONNECT_FAIL, StreamID: 2, SequenceNum: 21, Priority: 3},
		{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 3, SequenceNum: 1, Priority: 4},
	}
	for _, packet := range packets {
		if !scheduler.Enqueue(QueueTargetStream, packet) {
			t.Fatalf("failed to enqueue packet: %+v", packet)
		}
	}

	result, ok := scheduler.Dequeue()
	if !ok {
		t.Fatal("expected dequeue result")
	}
	if result.Packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		t.Fatalf("expected packed control blocks, got packet type=%d", result.Packet.PacketType)
	}
	if result.PackedBlocks != 3 {
		t.Fatalf("unexpected packed block count: got=%d want=3", result.PackedBlocks)
	}
	if len(result.Packet.Payload) != 3*PackedControlBlockSize {
		t.Fatalf("unexpected packed payload size: got=%d", len(result.Packet.Payload))
	}

	next, ok := scheduler.Dequeue()
	if !ok || next.Packet.PacketType != Enums.PACKET_STREAM_DATA || next.Packet.StreamID != 3 {
		t.Fatalf("expected round-robin to move to the next owner after packed dequeue, got=%+v ok=%v", next.Packet, ok)
	}

	last, ok := scheduler.Dequeue()
	if !ok || last.Packet.PacketType != Enums.PACKET_SOCKS5_CONNECT_FAIL || last.Packet.StreamID != 2 {
		t.Fatalf("expected remaining owner-local control packet last, got=%+v ok=%v", last.Packet, ok)
	}
}

func TestSchedulerPacksDNSAckControlBlocks(t *testing.T) {
	scheduler := NewScheduler(4)
	packets := []QueuedPacket{
		{PacketType: Enums.PACKET_DNS_QUERY_REQ_ACK, StreamID: 0, SequenceNum: 10, FragmentID: 0, TotalFragments: 2},
		{PacketType: Enums.PACKET_DNS_QUERY_REQ_ACK, StreamID: 0, SequenceNum: 10, FragmentID: 1, TotalFragments: 2},
	}
	for _, packet := range packets {
		if !scheduler.Enqueue(QueueTargetMain, packet) {
			t.Fatalf("failed to enqueue packet: %+v", packet)
		}
	}

	result, ok := scheduler.Dequeue()
	if !ok {
		t.Fatal("expected dequeue result")
	}
	if result.Packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		t.Fatalf("expected packed control blocks, got packet type=%d", result.Packet.PacketType)
	}
	if result.PackedBlocks != 2 {
		t.Fatalf("unexpected packed block count: got=%d want=2", result.PackedBlocks)
	}

	var fragments []uint8
	ForEachPackedControlBlock(result.Packet.Payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if packetType != Enums.PACKET_DNS_QUERY_REQ_ACK {
			t.Fatalf("unexpected packed packet type: got=%d want=%d", packetType, Enums.PACKET_DNS_QUERY_REQ_ACK)
		}
		if streamID != 0 || sequenceNum != 10 || totalFragments != 2 {
			t.Fatalf("unexpected packed dns ack metadata: stream=%d seq=%d total=%d", streamID, sequenceNum, totalFragments)
		}
		fragments = append(fragments, fragmentID)
		return true
	})
	if len(fragments) != 2 || fragments[0] != 0 || fragments[1] != 1 {
		t.Fatalf("unexpected packed dns ack fragments: %v", fragments)
	}
}

func TestSchedulerSkipsPingWhenRealTrafficExists(t *testing.T) {
	scheduler := NewScheduler(1)
	if !scheduler.Enqueue(QueueTargetMain, QueuedPacket{
		PacketType: Enums.PACKET_PING,
		StreamID:   0,
		Priority:   2,
	}) {
		t.Fatal("failed to enqueue ping")
	}
	if !scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    8,
		SequenceNum: 1,
		Priority:    2,
	}) {
		t.Fatal("failed to enqueue data")
	}

	result, ok := scheduler.Dequeue()
	if !ok || result.Packet.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected data to win over ping, got=%+v ok=%v", result.Packet, ok)
	}
	if scheduler.Pending() != 0 {
		t.Fatalf("expected ping to be dropped after data was preferred, pending=%d", scheduler.Pending())
	}
}

func TestSchedulerHandleStreamResetKeepsOnlyResetControlsInMain(t *testing.T) {
	scheduler := NewScheduler(4)
	queued := []struct {
		target QueueTarget
		packet QueuedPacket
	}{
		{QueueTargetStream, QueuedPacket{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 4, SequenceNum: 1, Priority: 2}},
		{QueueTargetMain, QueuedPacket{PacketType: Enums.PACKET_STREAM_FIN_ACK, StreamID: 4, SequenceNum: 2, Priority: 0}},
		{QueueTargetMain, QueuedPacket{PacketType: Enums.PACKET_STREAM_RST, StreamID: 4, SequenceNum: 3, Priority: 0}},
		{QueueTargetMain, QueuedPacket{PacketType: Enums.PACKET_STREAM_RST_ACK, StreamID: 4, SequenceNum: 4, Priority: 0}},
		{QueueTargetStream, QueuedPacket{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 9, SequenceNum: 1, Priority: 2}},
	}
	for _, queuedPacket := range queued {
		if !scheduler.Enqueue(queuedPacket.target, queuedPacket.packet) {
			t.Fatalf("failed to enqueue packet: %+v", queuedPacket.packet)
		}
	}

	dropped := scheduler.HandleStreamReset(4)
	if dropped != 2 {
		t.Fatalf("unexpected dropped count: got=%d want=2", dropped)
	}

	first, ok := scheduler.Dequeue()
	if !ok {
		t.Fatal("expected first packet after stream reset")
	}
	second, ok := scheduler.Dequeue()
	if !ok {
		t.Fatal("expected second packet after stream reset")
	}

	packedSeen := false
	dataSeen := false
	for _, result := range []DequeueResult{first, second} {
		switch {
		case result.Packet.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS:
			if result.PackedBlocks != 2 {
				t.Fatalf("expected packed reset block count=2, got=%d", result.PackedBlocks)
			}
			packedSeen = true
		case result.Packet.PacketType == Enums.PACKET_STREAM_DATA && result.Packet.StreamID == 9:
			dataSeen = true
		default:
			t.Fatalf("unexpected packet after stream reset: %+v", result.Packet)
		}
	}
	if !packedSeen || !dataSeen {
		t.Fatalf("expected both packed reset controls and unrelated stream data, packed=%v data=%v", packedSeen, dataSeen)
	}
}

func TestSchedulerRejectsPacketsThatMustNotEnterQueues(t *testing.T) {
	scheduler := NewScheduler(1)
	if scheduler.Enqueue(QueueTargetMain, QueuedPacket{
		PacketType: Enums.PACKET_PACKED_CONTROL_BLOCKS,
	}) {
		t.Fatal("PACKED_CONTROL_BLOCKS should never be queued directly")
	}
}
