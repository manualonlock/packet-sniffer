package parsing

import (
	"encoding/binary"
	"fmt"
	units "packet_sniffer/model"
)

type EthernetParser struct {
}

func (p *EthernetParser) Parse(buf []byte) (*units.PDU, error) {
	h := make(map[string]units.Header, 3)

	h["destMac"] = units.Header{HumanReadableValue: p.formatMac(buf[:6]), Value: buf[:6]}
	h["srcMac"] = units.Header{HumanReadableValue: p.formatMac(buf[6:12]), Value: buf[6:12]}
	h["etherType"] = units.Header{HumanReadableValue: "TODO", Value: buf[12:14]}

	return &units.PDU{
		Headers:  h,
		Payload:  buf[14:],
		Protocol: units.ETHERNET,
	}, nil
}

func (p *EthernetParser) GetNextProtocol(pdu *units.PDU) units.Protocol {

	var etherType = pdu.Headers["etherType"].Value

	switch binary.BigEndian.Uint16(etherType) {
	case 0x0800:
		return units.IPv4
	}
	return units.UNKNOWN
}

func (p *EthernetParser) formatMac(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (p *EthernetParser) formatEtherType(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
