// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package basecodec

import (
	"encoding/base32"
)

var lowerBase32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func EncodeLowerBase32(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	out := make([]byte, lowerBase32Encoding.EncodedLen(len(data)))
	lowerBase32Encoding.Encode(out, data)
	return string(out)
}

func DecodeLowerBase32(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	// Fast path: check if normalization is needed (tunnel data is always lowercase)
	needsNormalize := false
	for _, ch := range data {
		if ch >= 'A' && ch <= 'Z' {
			needsNormalize = true
			break
		}
	}

	src := data
	if needsNormalize {
		normalized := make([]byte, len(data))
		for i, ch := range data {
			if ch >= 'A' && ch <= 'Z' {
				normalized[i] = ch + ('a' - 'A')
				continue
			}
			normalized[i] = ch
		}
		src = normalized
	}

	out := make([]byte, lowerBase32Encoding.DecodedLen(len(src)))
	n, err := lowerBase32Encoding.Decode(out, src)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

func DecodeLowerBase32String(data string) ([]byte, error) {
	if data == "" {
		return []byte{}, nil
	}
	// Pass directly — DecodeLowerBase32 handles normalization only when needed
	return DecodeLowerBase32([]byte(data))
}
