// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package arq

import "sync"

const (
	defaultPayloadCapacity = 1500
	maxPayloadCapacity   = 8192
)

var payloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, defaultPayloadCapacity)
		return &b
	},
}

// AllocPayload returns a copy of src using a pooled byte slice to reduce GC pressure.
func AllocPayload(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	bufPtr := payloadPool.Get().(*[]byte)
	buf := *bufPtr
	if cap(buf) < len(src) {
		buf = make([]byte, len(src))
	} else {
		buf = buf[:len(src)]
	}
	copy(buf, src)
	return buf
}

// FreePayload explicitly returns the payload buf to the sync.Pool if size lies within bounds.
func FreePayload(buf []byte) {
	if buf != nil && cap(buf) >= defaultPayloadCapacity && cap(buf) <= maxPayloadCapacity {
		payloadPool.Put(&buf)
	}
}

// GetCapacityPayload gets a clean byte array for operations like packing blocks.
func GetCapacityPayload(capacity int) []byte {
	if capacity <= 0 {
		return nil
	}
	bufPtr := payloadPool.Get().(*[]byte)
	buf := *bufPtr
	if cap(buf) < capacity {
		buf = make([]byte, 0, capacity)
	} else {
		buf = buf[:0]
	}
	return buf
}
