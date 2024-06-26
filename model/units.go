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

var ProtocolStringMap = map[Protocol]string{
	ETHERNET:             "ETHERNET",
	ARP:                  "ARP",
	IPv4:                 "IPv4",
	IPv6:                 "IPv6",
	TCP:                  "TCP",
	ICMP:                 "ICMP",
	UDP:                  "UDP",
	VLAN_TAGGED:          "VLAN_TAGGED",
	LINK_LAYER_DISCOVERY: "LINK_LAYER_DISCOVERY",
}

type Header struct {
	Value              []byte
	HumanReadableValue string
}

type PDU struct {
	Headers map[string]Header
	Protocol
	NextPDU *PDU
	PrevPDU *PDU
	Payload []byte
}
