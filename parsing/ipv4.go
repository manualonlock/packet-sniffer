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

func (p *IPV4Parser) Parse(buf []byte) (*units.PDU, error) {
	h := make(map[string]units.Header, 13)

	version := buf[0] >> 4

	h["version"] = units.Header{Value: []byte{version}, HumanReadableValue: strconv.FormatUint(uint64(version), 10)} // IPv4 packets are always of the same version

	headerLength := buf[0] & 0b00001111
	h["headerLength"] = units.Header{
		Value:              []byte{headerLength},
		HumanReadableValue: strconv.FormatUint(uint64(headerLength), 10),
	}

	DSCP := buf[1]

	h["serviceType"] = units.Header{
		Value:              []byte{DSCP},
		HumanReadableValue: dscpName(DSCP),
	}

	packetLength := buf[2:4]
	h["packetLength"] = units.Header{
		Value:              packetLength,
		HumanReadableValue: strconv.FormatUint(uint64(binary.BigEndian.Uint16(packetLength)), 10),
	}

	identication := buf[4:6]
	h["identication"] = units.Header{
		Value:              identication,
		HumanReadableValue: strconv.FormatUint(uint64(binary.BigEndian.Uint16(identication)), 16),
	}

	flags := binary.BigEndian.Uint16(buf[6:8]) >> 13
	h["flags"] = units.Header{
		Value:              []byte{byte(flags)},
		HumanReadableValue: strconv.FormatUint(uint64(flags), 2),
	}

	fragmentationOffset := binary.BigEndian.Uint16(buf[6:8]) & 0b0001111111111111
	h["fragmentationOffset"] = units.Header{
		Value:              []byte{byte(fragmentationOffset)},
		HumanReadableValue: strconv.FormatUint(uint64(fragmentationOffset), 10),
	}

	TTL := buf[8:9]
	h["TTL"] = units.Header{
		Value:              TTL,
		HumanReadableValue: strconv.FormatUint(uint64(TTL[0]), 10),
	}

	protocolHeader := buf[9:10]
	protocol := IPv4ProtocolHeaderMap[protocolHeader[0]]

	protocolHR := units.ProtocolStringMap[protocol]

	h["protocol"] = units.Header{
		Value:              protocolHeader,
		HumanReadableValue: protocolHR,
	}

	headerChecksum := buf[10:12]
	h["headerChecksum"] = units.Header{
		Value:              headerChecksum,
		HumanReadableValue: strconv.FormatUint(uint64(binary.BigEndian.Uint16(headerChecksum)), 10),
	}

	h["sourceIP"] = units.Header{
		Value:              buf[12:16],
		HumanReadableValue: convertToIP(buf[12:16]),
	}

	h["destIP"] = units.Header{
		Value:              buf[16:20],
		HumanReadableValue: convertToIP(buf[16:20]),
	}
	return &units.PDU{
		Headers:  h,
		Payload:  buf[headerLength*4:],
		Protocol: units.IPv4,
	}, nil
}

func (p *IPV4Parser) GetNextProtocol(pdu *units.PDU) units.Protocol {
	return units.UNKNOWN
}
