package units

type Protocol int8

const (
	UNKNOWN Protocol = iota - 1
	ETHERNET
	ARP
	IPv4
	IPv6
	ICMP
	TCP
	UDP
	VLAN_TAGGED
	LINK_LAYER_DISCOVERY
)

type ProtocolName struct {
	Shortened string
	Full      string
}

var ProtocolStringMap = map[Protocol]ProtocolName{
	ETHERNET:             {"Ethernet", "Ethernet Protocol"},
	ARP:                  {"ARP", "Address Resolution Protocol"},
	IPv4:                 {"IPv4", "Internet Protocol version 4"},
	IPv6:                 {"IPv6", "Internet Protocol version 6"},
	TCP:                  {"TCP", "Transmission Control Protocol"},
	ICMP:                 {"ICMP", "Internet Control Message Protocol"},
	UDP:                  {"UDP", "User Datagram Protocol"},
	VLAN_TAGGED:          {"VLAN", "Virtual Local Area Network"},
	LINK_LAYER_DISCOVERY: {"LLDP", "Link Layer Discovery Protocol"},
}

type PDUHeaderKey uint8

type Header []byte

type PDU struct {
	Headers map[PDUHeaderKey]Header
	Protocol
	NextPDU *PDU
	PrevPDU *PDU
	Payload []byte
}
