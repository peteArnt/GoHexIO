package srec

import (
	"encoding/hex"
)

// Awkward name, but essentially we're taking an ASCII Hexadecimal string
// (two chars per byte) and calculating the checksum of the binary
// equivelant.
func calcChecksumHexAscii(s string) (byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	return calcChecksum(b), nil
}

// S-Record checksum algorithm
func calcChecksum(b []byte) byte {
	var cs byte
	for _, v := range b {
		cs += v
	}
	return ^cs
}
