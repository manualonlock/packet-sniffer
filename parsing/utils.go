package parsing

import (
	units "packet_sniffer/model"
)

func ParserFromProtocol(protocol units.Protocol) Parser {
	switch protocol {
	case units.ETHERNET:
		return EthernetParser{}
	case units.IPv4:
		return IPV4Parser{}
	case units.ARP:
		return ArpParser{}
	default:
		return nil
	}
}
