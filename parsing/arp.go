package parsing

import (
	"encoding/binary"
	"fmt"
	units "packet_sniffer/model"
	"strconv"
)

const (
	hardwareTypeArp units.PDUHeaderKey = iota + 2
	protocolTypeArp
	hardwareLengthArp
	protocolLengthArp
	operationArp
	senderHardwareAddressArp
	senderProtocolAddressArp
	targetHardwareAddressArp
	targetProtocolAddressArp
)

const ArpRequest = 1
const ArpReply = 2

var operationCodeName = map[uint16]string{
	ArpRequest: "ARP Request",
	ArpReply:   "ARP Reply",
	3:          "RARP Request",
	4:          "RARP Reply",
	5:          "DRARP Request",
	6:          "DRARP Reply",
	7:          "DRARP error",
	8:          "InARP Request",
	9:          "InARP Reply",
}

var arpHeaderNames = map[units.PDUHeaderKey]string{
	hardwareTypeArp:          "Hardware Type",
	protocolTypeArp:          "Protocol Type",
	hardwareLengthArp:        "Hardware Length",
	protocolLengthArp:        "Protocol Length",
	operationArp:             "Operation",
	senderHardwareAddressArp: "Sender Hardware Address",
	senderProtocolAddressArp: "Sender Protocol Address",
	targetHardwareAddressArp: "Target Hardware Address",
	targetProtocolAddressArp: "Target Protocol Address",
}

var arpHTypes = map[uint16]string{
	1:  "Ethernet (10Mb)",
	2:  "Experimental Ethernet (3Mb)",
	3:  "Amateur Radio AX.25",
	4:  "Proteon ProNET Token Ring",
	5:  "Chaos",
	6:  "IEEE 802 Networks",
	7:  "ARCNET",
	8:  "Hyperchannel",
	9:  "Lanstar",
	10: "Autonet Short Address",
	11: "LocalTalk",
	12: "LocalNet (IBM PCNet or SYTEK LocalNET)",
	13: "Ultra link",
	14: "SMDS",
	15: "Frame Relay",
	16: "Asynchronous Transmission Mode (ATM)",
	17: "HDLC",
	18: "Fibre Channel",
	19: "Asynchronous Transmission Mode (ATM) 2",
	20: "Serial Line",
	21: "Asynchronous Transmission Mode (ATM) 3",
	22: "MIL-STD-188-220",
	23: "Metricom",
	24: "IEEE 1394.1995",
	25: "MAPOS",
	26: "Twinaxial",
	27: "EUI-64",
	28: "HIPARP",
	29: "IP and ARP over ISO 7816-3",
	30: "ARPSec",
	31: "IPsec tunnel",
	32: "InfiniBand (TM)",
	33: "TIA-102 Project 25 Common Air Interface (CAI)",
	34: "Wiegand Interface",
	35: "Pure IP",
	36: "HW_EXP1",
	37: "HFI",
}

type ArpParser struct{}

func (p ArpParser) Parse(buf []byte) (*units.PDU, error) {
	h := make(map[units.PDUHeaderKey]units.Header, 9)
	h[hardwareTypeArp] = buf[0:2]
	h[protocolTypeArp] = buf[2:4]
	h[hardwareLengthArp] = buf[4:5]
	h[protocolLengthArp] = buf[5:6]
	h[operationArp] = buf[6:8]

	hardwareAddressLength := int8(h[hardwareLengthArp][0])
	protocolLength := int8(h[protocolLengthArp][0])
	lastIndex := 8 + hardwareAddressLength

	h[senderHardwareAddressArp] = buf[8:lastIndex]
	h[senderProtocolAddressArp] = buf[lastIndex : lastIndex+protocolLength]
	lastIndex += protocolLength
	h[targetHardwareAddressArp] = buf[lastIndex : lastIndex+hardwareAddressLength]
	lastIndex += hardwareAddressLength
	h[targetProtocolAddressArp] = buf[lastIndex : lastIndex+protocolLength]
	return &units.PDU{
		Headers:  h,
		Protocol: units.ARP,
		Payload:  []byte{},
	}, nil
}

func (p ArpParser) GetNextProtocol(pdu *units.PDU) units.Protocol {
	return units.UNKNOWN
}

func (p ArpParser) HeaderName(header units.PDUHeaderKey) string {
	return arpHeaderNames[header]
}

func (p ArpParser) HeaderToHumanReadable(headerKey units.PDUHeaderKey, pdu *units.PDU) string {
	htype := binary.BigEndian.Uint16(pdu.Headers[hardwareTypeArp])
	isEthernet := htype == 1
	protocol := EthernetParser{}.ProtocolFromEtherType(pdu.Headers[protocolTypeArp])
	header := pdu.Headers[headerKey]
	switch headerKey {
	case hardwareTypeArp:
		return arpHTypes[htype]
	case protocolTypeArp:
		return units.ProtocolStringMap[protocol].Shortened
	case operationArp:
		return operationCodeName[binary.BigEndian.Uint16(header)]
	case hardwareLengthArp, protocolLengthArp:
		return strconv.FormatInt(int64(header[0]), 10)
	}

	if isEthernet {
		switch headerKey {
		case senderHardwareAddressArp, targetHardwareAddressArp:
			return formatMac(header)
		case senderProtocolAddressArp, targetProtocolAddressArp:
			if protocol == units.IPv4 {
				return convertToIP(header)
			} else {
				return "Non-IPv4 ARP requests are not yet supported"
			}
		}
		return ""
	} else {
		return "Non-Ethernet LAN's are not yet supported"
	}
}

func (p ArpParser) MostSignificantHeaders(*units.PDU) []units.PDUHeaderKey {
	return []units.PDUHeaderKey{protocolTypeArp, senderHardwareAddressArp, targetProtocolAddressArp, senderProtocolAddressArp, targetProtocolAddressArp}
}

func (p ArpParser) HeaderBreakdown(headerKey units.PDUHeaderKey, pdu *units.PDU) PDUBreakdownOutput {
	header := pdu.Headers[headerKey]
	return PDUBreakdownOutput{
		KeyName: p.HeaderName(headerKey),
		Value:   p.HeaderToHumanReadable(headerKey, pdu),
		Header:  &header,
	}
}

func (p ArpParser) ArpOperationBreakdown(pdu *units.PDU) PDUBreakdownOutput {
	r := p.HeaderBreakdown(operationArp, pdu)
	opCode := binary.BigEndian.Uint16(pdu.Headers[operationArp])
	var desc *string
	if opCode == ArpRequest {
		d := fmt.Sprintf("Who has the address %s?", p.HeaderToHumanReadable(targetProtocolAddressArp, pdu))
		desc = &d
	} else if opCode == ArpReply {
		d := fmt.Sprintf("I'm the one who has the address %s", p.HeaderToHumanReadable(senderProtocolAddressArp, pdu))
		desc = &d
	}
	r.Description = desc
	return r

}

func (p ArpParser) PDUBreakdown(pdu *units.PDU) []PDUBreakdownOutput {
	r := make([]PDUBreakdownOutput, 9)
	r[0] = p.HeaderBreakdown(hardwareTypeArp, pdu)
	r[1] = p.HeaderBreakdown(protocolTypeArp, pdu)
	r[2] = p.HeaderBreakdown(hardwareLengthArp, pdu)
	r[3] = p.HeaderBreakdown(protocolLengthArp, pdu)
	r[4] = p.ArpOperationBreakdown(pdu)
	r[5] = p.HeaderBreakdown(senderHardwareAddressArp, pdu)
	r[6] = p.HeaderBreakdown(senderProtocolAddressArp, pdu)
	r[7] = p.HeaderBreakdown(targetHardwareAddressArp, pdu)
	r[8] = p.HeaderBreakdown(targetProtocolAddressArp, pdu)
	return r
}
