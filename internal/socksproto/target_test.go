// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package socksproto

import "testing"

func TestParseTargetPayloadIPv4(t *testing.T) {
	target, err := ParseTargetPayload([]byte{0x01, 127, 0, 0, 1, 0x01, 0xBB})
	if err != nil {
		t.Fatalf("ParseTargetPayload returned error: %v", err)
	}
	if target.Host != "127.0.0.1" || target.Port != 443 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestParseTargetPayloadDomain(t *testing.T) {
	target, err := ParseTargetPayload([]byte{0x03, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x35})
	if err != nil {
		t.Fatalf("ParseTargetPayload returned error: %v", err)
	}
	if target.Host != "example.com" || target.Port != 53 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestParseTargetPayloadRejectsUnsupportedType(t *testing.T) {
	if _, err := ParseTargetPayload([]byte{0x05, 0x00, 0x35}); err != ErrUnsupportedAddressType {
		t.Fatalf("unexpected error: %v", err)
	}
}
