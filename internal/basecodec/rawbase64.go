// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package basecodec

import "encoding/base64"

func EncodeRawBase64(data []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}

	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(data)))
	base64.RawStdEncoding.Encode(out, data)
	return out
}

func DecodeRawBase64(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
	n, err := base64.RawStdEncoding.Decode(out, data)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}
