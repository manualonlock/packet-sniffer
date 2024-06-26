package services

import (
	units "packet_sniffer/model"
	"packet_sniffer/parsing"
)

type Parser struct {
	EthernetParser parsing.Parser
	IPv4Parser     parsing.Parser
}

func (p *Parser) Parse(initialFrame []byte) (*units.PDU, error) {

	protocol := units.ETHERNET
	currentBuf := initialFrame
	var PDUS []units.PDU

	for protocol != units.UNKNOWN {
		parser := *p.ParserFromProtocol(protocol)
		pdu, err := parser.Parse(currentBuf)
		if err != nil {
			return nil, err
		}
		currentBuf = pdu.Payload
		PDUS = append(PDUS, *pdu)
		protocol = parser.GetNextProtocol(pdu)
	}

	for i := 0; i < len(PDUS)-1; i++ {
		PDUS[i].NextPDU, PDUS[i+1].PrevPDU = &PDUS[i+1], &PDUS[i]
	}

	return &PDUS[0], nil
}

func (p *Parser) ParserFromProtocol(protocol units.Protocol) *parsing.Parser {
	var parser *parsing.Parser
	switch protocol {
	case units.ETHERNET:
		parser = &p.EthernetParser
	case units.IPv4:
		parser = &p.IPv4Parser
	default:
		return nil
	}
	return parser
}
