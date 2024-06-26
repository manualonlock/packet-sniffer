package utils

import (
	"math"
	"math/bits"
)

func ByteArrayShift(bytes []byte, start int, end int) []byte {
	bytesCP := bytes[:]
	if int(math.Floor(float64(end)/8)) != len(bytesCP) {
		byteToCut := int(math.Floor(float64(end / 8)))
		bytesCP[byteToCut] = bytesCP[byteToCut] & (0b11111111 >> (8 - (end % 8)))
		for i := byteToCut + 1; i < len(bytesCP); i++ {
			bytesCP[i] = 0
		}
	}

	for i := 0; i < len(bytes)-1; i++ {
		bytesCP[i] = bytesCP[i+1]<<(8-start) | bytesCP[i]>>start
	}
	if len(bytes) > 1 {
		bytesCP[len(bytes)-1] = bytesCP[len(bytes)-1] >> start
	}

	return bytesCP
}

func BitwiseSlice(bytes []byte, start int, end int) []byte {
	// Buffer should be used instead of bytes slice
	if start >= end {
		return []byte{}
	}
	buf := make([]byte, 0)
	for i := 0; i <= len(bytes); i++ {
		bitSegmentStart := i * 8
		bitSegmentEnd := bitSegmentStart + 8

		if bitSegmentEnd < start {
			continue
		}
		buf = append(buf, bytes[i])
		if bitSegmentEnd >= end {
			break
		}
	}
	// This piece of crap is to be removed
	buf = append(buf, 0)
	s := start % 8
	e := s + (end - start)
	return ByteArrayShift(buf, s, e)
}

func BytesReverse(bytes []byte) []byte {
	cp := make([]byte, len(bytes))
	for i, b := range bytes {
		cp[i] = bits.Reverse8(b)
	}
	return cp
}
