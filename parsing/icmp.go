package parsing

import (
	"encoding/binary"
	"fmt"
	units "packet_sniffer/model"
	"strconv"
	"time"
)

type ICMPParser struct{}

const (
	typeICMP units.PDUHeaderKey = iota + 2
	codeICMP
	checksumICMP
	restOfTheHeaderICMP
	identifierICMP
	sequenceNumberICMP
	optionalDataICMP
	originalTimestampICMP
	receiveTimestampICMP
	transmitTimestampICMP
	pointerICMP
	unusedICMP
	datagramPart
)

var icmpHeaderNames = map[units.PDUHeaderKey]string{
	typeICMP:              "Type",
	codeICMP:              "Code",
	checksumICMP:          "Checksum",
	restOfTheHeaderICMP:   "Rest Of The Header",
	identifierICMP:        "Identifier",
	sequenceNumberICMP:    "Sequence Number",
	optionalDataICMP:      "Optional Data",
	originalTimestampICMP: "Original Timestamp",
	receiveTimestampICMP:  "Receive Timestamp",
	transmitTimestampICMP: "Transmit Timestamp",
	pointerICMP:           "Pointer",
	unusedICMP:            "Unused",
	datagramPart:          "User Datagram Protocol",
}

var icmpMessageTypes = map[byte]string{
	0:  "Echo Reply",
	3:  "Destination Unreachable",
	4:  "Source Quench",
	5:  "Redirect Message",
	8:  "Echo Request",
	11: "Time Exceeded",
	12: "Parameter Problem",
	13: "Timestamp",
	14: "Timestamp Reply",
}

func (p ICMPParser) Parse(buf []byte) (*units.PDU, error) {
	h := make(map[units.PDUHeaderKey]units.Header, 10) //TODO allocate precise amount of memory
	h[typeICMP] = buf[0:1]
	h[codeICMP] = buf[1:2]
	h[checksumICMP] = buf[2:4]
	switch buf[0] {
	// echo request / reply
	case 8, 0:
		h[identifierICMP] = buf[4:6]
		h[sequenceNumberICMP] = buf[6:8]
		h[optionalDataICMP] = buf[8:] // TODO could be other useful data within the optional data
	// timestamp echo request / reply
	case 13, 14:
		h[identifierICMP] = buf[4:6]
		h[sequenceNumberICMP] = buf[6:8]

		h[originalTimestampICMP] = buf[8:12]
		h[receiveTimestampICMP] = buf[12:16]
		h[transmitTimestampICMP] = buf[16:20]
	// parameter problems
	case 12:
		h[pointerICMP] = buf[4:5]
		h[unusedICMP] = buf[5:8]
		h[datagramPart] = buf[8:]
	// other error types
	case 3, 4, 11, 5:
		h[unusedICMP] = buf[4:8]
		h[datagramPart] = buf[8:]
	}
	return &units.PDU{
		Headers:  h,
		Protocol: units.ICMP,
		Payload:  nil,
	}, nil
}

func (p ICMPParser) GetNextProtocol(pdu *units.PDU) units.Protocol {
	return units.UNKNOWN
}

func (p ICMPParser) HeaderName(header units.PDUHeaderKey) string {
	return icmpHeaderNames[header]
}

func (p ICMPParser) HeaderToHumanReadable(headerKey units.PDUHeaderKey, pdu *units.PDU) string {
	h := pdu.Headers[headerKey]
	switch headerKey {
	case typeICMP:
		return icmpMessageTypes[h[0]]
	case codeICMP:
		return strconv.FormatUint(uint64(h[0]), 10)
	case checksumICMP:
		return fmt.Sprintf("0x%02x", h) // TODO Validate whether the checksum is correct
	case identifierICMP:
		return fmt.Sprintf("0x%02x", h)
	case optionalDataICMP:
		return fmt.Sprintf("%02x", h) //TODO ICMP client might include some meaningful data into the optional data header
	case sequenceNumberICMP:
		return fmt.Sprintf("0x%02x", h)
	case originalTimestampICMP, receiveTimestampICMP, transmitTimestampICMP:
		timestamp := binary.BigEndian.Uint16(h)
		t := time.Unix(int64(timestamp)*1000, 0)
		return t.String()
	}
	return ""
}

func (p ICMPParser) MostSignificantHeaders(pdu *units.PDU) []units.PDUHeaderKey {
	switch pdu.Headers[typeICMP][0] {
	case 0, 8, 13, 14:
		return []units.PDUHeaderKey{typeICMP, codeICMP, identifierICMP}
	case 3, 4, 11, 5:
		return []units.PDUHeaderKey{typeICMP, codeICMP}
	case 12:
		return []units.PDUHeaderKey{typeICMP, codeICMP, pointerICMP}
	default:
		return []units.PDUHeaderKey{typeICMP, codeICMP}
	}
}

func (p ICMPParser) breakdownMessage(headerKey units.PDUHeaderKey, pdu *units.PDU) PDUBreakdownOutput {
	header := pdu.Headers[headerKey]
	return PDUBreakdownOutput{
		KeyName: icmpHeaderNames[headerKey],
		Value:   p.HeaderToHumanReadable(headerKey, pdu),
		Header:  &header,
	}
}

func (p ICMPParser) PDUBreakdownAsEchoMessage(pdu *units.PDU) []PDUBreakdownOutput {
	bdo := make([]PDUBreakdownOutput, 6)
	bdo[0] = p.breakdownMessage(typeICMP, pdu)

	bdo[1] = p.breakdownMessage(codeICMP, pdu)
	bdo[2] = p.breakdownMessage(checksumICMP, pdu)
	bdo[3] = p.breakdownMessage(identifierICMP, pdu)
	bdo[4] = p.breakdownMessage(sequenceNumberICMP, pdu)
	bdo[5] = p.breakdownMessage(optionalDataICMP, pdu)

	return bdo
}

func (p ICMPParser) PDUBreakdownAsEchoTimestampMessage(pdu *units.PDU) []PDUBreakdownOutput {
	bdo := make([]PDUBreakdownOutput, 6)
	bdo[0] = p.breakdownMessage(typeICMP, pdu)

	bdo[1] = p.breakdownMessage(codeICMP, pdu)
	bdo[2] = p.breakdownMessage(checksumICMP, pdu)
	bdo[3] = p.breakdownMessage(identifierICMP, pdu)
	bdo[4] = p.breakdownMessage(sequenceNumberICMP, pdu)
	bdo[5] = p.breakdownMessage(originalTimestampICMP, pdu)
	bdo[6] = p.breakdownMessage(receiveTimestampICMP, pdu)
	bdo[7] = p.breakdownMessage(transmitTimestampICMP, pdu)
	return bdo
}

func (p ICMPParser) PDUBreakdownAsParametersError(pdu *units.PDU) []PDUBreakdownOutput {

}

func (p ICMPParser) PDUBreakdown(pdu *units.PDU) []PDUBreakdownOutput {
	messageType, _ := pdu.Headers[typeICMP]
	switch messageType[0] {
	case 0, 8:
		return p.PDUBreakdownAsEchoMessage(pdu)
	case 13, 14:
		return p.PDUBreakdownAsEchoTimestampMessage(pdu)
	case 12:

	}
	return []PDUBreakdownOutput{}
}
