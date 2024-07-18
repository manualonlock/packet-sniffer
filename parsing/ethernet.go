package parsing

import (
	"encoding/binary"
	"fmt"
	units "packet_sniffer/model"
)

type EthernetParser struct {
}

const (
	srcMac units.PDUHeaderKey = iota
	dstMac
	etherType
)

var etherHeaderNames = map[units.PDUHeaderKey]string{
	dstMac:    "Dst",
	srcMac:    "Src",
	etherType: "etherType",
}

var etherTypeMap = map[int]units.Protocol{
	0x0800: units.IPv4,
	0x0806: units.ARP,
}

func (p EthernetParser) Parse(buf []byte) (*units.PDU, error) {
	h := make(map[units.PDUHeaderKey]units.Header, 3)
	h[dstMac] = buf[:6]
	h[srcMac] = buf[6:12]
	h[etherType] = buf[12:14]

	return &units.PDU{
		Headers:  h,
		Payload:  buf[14:],
		Protocol: units.ETHERNET,
	}, nil
}

func (p EthernetParser) HeaderToHumanReadable(headerKey units.PDUHeaderKey, pdu *units.PDU) string {
	header := pdu.Headers[headerKey]
	switch headerKey {
	case dstMac, srcMac:
		return formatMac(header)
	case etherType:
		var protocolShortenedName string
		protocolName, hit := units.ProtocolStringMap[p.ProtocolFromEtherType(header)]
		if hit == true {
			protocolShortenedName = protocolName.Shortened
		}
		return protocolShortenedName
	}
	return ""
}

func (p EthernetParser) ProtocolFromEtherType(ethTypeHeader []byte) units.Protocol {
	v, hit := etherTypeMap[int(binary.BigEndian.Uint16(ethTypeHeader))]
	if hit == true {
		return v
	} else {
		return units.UNKNOWN
	}
}

func (p EthernetParser) GetNextProtocol(pdu *units.PDU) units.Protocol {
	var ethType = pdu.Headers[etherType]
	return p.ProtocolFromEtherType(ethType)
}

func (p EthernetParser) formatEtherType(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (p EthernetParser) MostSignificantHeaders() []units.PDUHeaderKey {
	return []units.PDUHeaderKey{dstMac, srcMac, etherType}
}

func (p EthernetParser) HeaderName(header units.PDUHeaderKey) string {
	return etherHeaderNames[header]
}

func (p EthernetParser) PDUBreakdown(pdu *units.PDU) []PDUBreakdownOutput {
	output := make([]PDUBreakdownOutput, 3)
	output[0] = PDUBreakdownOutput{KeyName: "Destination", Value: p.HeaderToHumanReadable(dstMac, pdu)}
	output[1] = PDUBreakdownOutput{KeyName: "Source", Value: p.HeaderToHumanReadable(srcMac, pdu)}
	output[2] = PDUBreakdownOutput{KeyName: "Type", Value: p.HeaderToHumanReadable(etherType, pdu)}
	return output
}

func formatMac(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
