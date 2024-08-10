package parsing

import (
	"encoding/binary"
	"fmt"
	"net"
	units "packet_sniffer/model"
	"strconv"
)

type IPV4Parser struct {
}

const (
	srcIP units.PDUHeaderKey = iota
	dstIP
	versionIP
	headerLengthIP
	DSCPIP
	ECNIP
	packetLengthIP
	identificationIP
	flagsIP
	fragmentationOffsetIP
	ttlIP
	protocolIP
	headerChecksumIP
)

var ipHeaderNames = map[units.PDUHeaderKey]string{
	srcIP:                 "Src",
	dstIP:                 "Dst",
	versionIP:             "Version",
	headerLengthIP:        "Header Length",
	DSCPIP:                "Service Type",
	packetLengthIP:        "Packet Length",
	identificationIP:      "Identification",
	flagsIP:               "Flags",
	fragmentationOffsetIP: "Fragmentation Offset",
	ttlIP:                 "TTL",
	protocolIP:            "Protocol",
	headerChecksumIP:      "Header Checksum",
}

var dscpMap = map[byte]string{
	0:  "CS0",
	8:  "CS1",
	16: "CS2",
	24: "CS3",
	32: "CS4",
	40: "CS5",
	48: "CS6",
	56: "CS7",
	46: "EF",
	10: "AF11",
	12: "AF12",
	14: "AF13",
	18: "AF21",
	20: "AF22",
	22: "AF23",
	26: "AF31",
	28: "AF32",
	30: "AF33",
	34: "AF41",
	36: "AF42",
	38: "AF43",
}

var ecnMap = map[byte]string{
	0: "Not-ECT",
	1: "ECT(1)",
	2: "ECT(2)",
	3: "Congestion Experienced",
}

var IPv4ProtocolHeaderMap = map[byte]units.Protocol{
	1:  units.ICMP,
	6:  units.TCP,
	17: units.UDP,
}

func dscpName(b byte) string {
	if name, exists := dscpMap[b]; exists {
		return name
	}
	return fmt.Sprintf("Unknown (DSCP %d)", b)
}

func convertToIP(b []byte) string {
	if len(b) != 4 {
		return "Invalid input: byte slice length is not 4"
	}
	ip := net.IPv4(b[0], b[1], b[2], b[3])
	return ip.String()
}

func (p IPV4Parser) Parse(buf []byte) (*units.PDU, error) {
	h := make(map[units.PDUHeaderKey]units.Header, 13)
	h[versionIP] = units.Header{buf[0] >> 4}
	headerLength := buf[0] & 0b00001111
	h[headerLengthIP] = units.Header{headerLength}
	h[DSCPIP] = units.Header{buf[1] >> 2}
	h[ECNIP] = units.Header{buf[1] >> 6}
	h[packetLengthIP] = buf[2:4]

	h[identificationIP] = buf[4:6]

	h[flagsIP] = []byte{buf[6] >> 5}
	fgOffset := (uint16(buf[6])&0x1F)<<8 | uint16(buf[7])
	fgOffsetBytes := []byte{byte(fgOffset >> 8), byte(fgOffset & 0xff)}
	h[fragmentationOffsetIP] = fgOffsetBytes

	h[ttlIP] = buf[8:9]
	h[protocolIP] = buf[9:10]

	h[headerChecksumIP] = buf[10:12]

	h[srcIP] = buf[12:16]
	h[dstIP] = buf[16:20]

	return &units.PDU{
		Headers:  h,
		Payload:  buf[headerLength*4:],
		Protocol: units.IPv4,
	}, nil
}

func (p IPV4Parser) getFragmentationOffsetHumanReadable(header []byte) string {
	fgOffest := binary.BigEndian.Uint16(header)
	return fmt.Sprintf(
		"%01b %04b %04b %04b",
		fgOffest>>15,
		fgOffest>>11&0x7,
		fgOffest>>7&0x7,
		fgOffest>>3&0x7,
	)
}

func (p IPV4Parser) HeaderToHumanReadable(headerKey units.PDUHeaderKey, pdu *units.PDU) string {
	header := pdu.Headers[headerKey]
	switch headerKey {
	case srcIP, dstIP:
		return convertToIP(header)
		// TODO fragmentationOffset
	case versionIP, headerLengthIP, ttlIP, headerChecksumIP:
		return strconv.FormatUint(uint64(header[0]), 10)
	case fragmentationOffsetIP:
		return p.getFragmentationOffsetHumanReadable(header)
	case DSCPIP:
		return dscpName(header[0])
	case packetLengthIP, identificationIP:
		return strconv.FormatUint(uint64(binary.BigEndian.Uint16(header)), 10)
	case flagsIP:
		return strconv.FormatUint(uint64(header[0]), 2)
	case protocolIP:
		protocol := IPv4ProtocolHeaderMap[header[0]]
		protocolName, hit := units.ProtocolStringMap[protocol]

		if hit == true {
			return protocolName.Shortened
		}
	}
	return "Unknown"
}

func (p IPV4Parser) GetNextProtocol(pdu *units.PDU) units.Protocol {
	protocol, _ := IPv4ProtocolHeaderMap[pdu.Headers[protocolIP][0]]
	if protocol == units.ICMP {
		return units.ICMP
	}
	return units.UNKNOWN
}

func (p IPV4Parser) MostSignificantHeaders(*units.PDU) []units.PDUHeaderKey {
	return []units.PDUHeaderKey{srcIP, dstIP}
}

func (p IPV4Parser) HeaderName(header units.PDUHeaderKey) string {
	return ipHeaderNames[header]
}

func (p IPV4Parser) firstByteBreakdown(pdu *units.PDU, header units.PDUHeaderKey) PDUBreakdownOutput {
	h := pdu.Headers[header]
	val := p.HeaderToHumanReadable(header, pdu)
	desc := fmt.Sprintf("%04b", h[0])
	return PDUBreakdownOutput{
		KeyName:     ipHeaderNames[header],
		Value:       fmt.Sprintf("%s", val),
		Header:      &h,
		Description: &desc,
	}
}

func (p IPV4Parser) differentiatedServicesBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[DSCPIP]
	hECN := pdu.Headers[ECNIP]
	desc := fmt.Sprintf("DSCP: %s, ECN: %s", dscpMap[h[0]], ecnMap[hECN[0]])
	return PDUBreakdownOutput{
		KeyName:     ipHeaderNames[DSCPIP],
		Value:       fmt.Sprintf("0x%02x", h[0]),
		Header:      &h,
		Description: &desc,
	}
}

func (p IPV4Parser) packetLengthBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[packetLengthIP]
	return PDUBreakdownOutput{
		KeyName: ipHeaderNames[packetLengthIP],
		Value:   fmt.Sprintf("%d", binary.BigEndian.Uint16(h)),
		Header:  &h,
	}
}

func (p IPV4Parser) IdentificationBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[identificationIP]
	hUint := binary.BigEndian.Uint16(h)
	return PDUBreakdownOutput{
		KeyName: ipHeaderNames[identificationIP],
		Value:   fmt.Sprintf("0x%04x (%d)", hUint, hUint),
		Header:  &h,
	}
}

var isFlagSet = map[byte]string{
	0: "Not Set",
	1: "Set",
}

func (p IPV4Parser) FlagsBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[flagsIP]
	val := h[0]
	reservedBitFlag := val >> 2
	dontFragmentFlag := (val >> 1) & 0b001
	MoreFragments := val & 0b001

	return PDUBreakdownOutput{
		KeyName:     ipHeaderNames[flagsIP],
		Value:       fmt.Sprintf("%03b", val),
		Header:      &h,
		Description: nil,
		InnerBreakdowns: []PDUBreakdownOutput{
			{
				KeyName: "Reserved bit",
				Value:   isFlagSet[reservedBitFlag],
			},
			{
				KeyName: "Don't fragment bit",
				Value:   isFlagSet[dontFragmentFlag],
			},
			{
				KeyName: "More Fragments",
				Value:   isFlagSet[MoreFragments],
			},
		},
	}
}

func (p IPV4Parser) FragmentationOffsetBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[fragmentationOffsetIP]
	return PDUBreakdownOutput{
		KeyName: ipHeaderNames[fragmentationOffsetIP],
		Value:   p.getFragmentationOffsetHumanReadable(h),
		Header:  &h,
	}
}

func (p IPV4Parser) ttlBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[ttlIP]
	val := p.HeaderToHumanReadable(ttlIP, pdu)
	return PDUBreakdownOutput{
		KeyName: ipHeaderNames[ttlIP],
		Value:   fmt.Sprintf("%s", val),
		Header:  &h,
	}
}

func (p IPV4Parser) protocolBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[protocolIP]
	protocolName := p.HeaderToHumanReadable(protocolIP, pdu)
	desc := fmt.Sprintf("%d", h[0])
	return PDUBreakdownOutput{
		KeyName:     ipHeaderNames[protocolIP],
		Value:       fmt.Sprintf("%s", protocolName),
		Header:      &h,
		Description: &desc,
	}
}

func (p IPV4Parser) headerChecksumBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	h := pdu.Headers[headerChecksumIP]

	return PDUBreakdownOutput{
		KeyName: ipHeaderNames[headerChecksumIP],
		Value:   fmt.Sprintf("0x%0x", binary.BigEndian.Uint16(h)),
		Header:  &h,
	}
}

func (p IPV4Parser) ipAddressBreakdown(pdu *units.PDU, addressKey units.PDUHeaderKey) PDUBreakdownOutput {
	h := pdu.Headers[addressKey]
	return PDUBreakdownOutput{
		KeyName: ipHeaderNames[addressKey],
		Value:   p.HeaderToHumanReadable(addressKey, pdu),
		Header:  &h,
	}
}

func (p IPV4Parser) PDUBreakdown(pdu *units.PDU) []PDUBreakdownOutput {
	bdo := make([]PDUBreakdownOutput, 12)
	bdo[0] = p.firstByteBreakdown(pdu, versionIP)
	bdo[1] = p.firstByteBreakdown(pdu, headerLengthIP)
	bdo[2] = p.differentiatedServicesBreakdown(pdu)
	bdo[3] = p.packetLengthBreakdown(pdu)
	bdo[4] = p.IdentificationBreakdown(pdu)
	bdo[5] = p.FlagsBreakdown(pdu)
	bdo[6] = p.FragmentationOffsetBreakdown(pdu)
	bdo[7] = p.ttlBreakdown(pdu)
	bdo[8] = p.protocolBreakdown(pdu)
	bdo[9] = p.headerChecksumBreakdown(pdu)
	bdo[10] = p.ipAddressBreakdown(pdu, srcIP)
	bdo[11] = p.ipAddressBreakdown(pdu, dstIP)
	return bdo
}
