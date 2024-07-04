package parsing

import (
	units "packet_sniffer/model"
)

type CompositeParser struct{}

func (p *CompositeParser) Parse(initialFrame []byte) (*units.PDU, error) {

	protocol := units.ETHERNET
	currentBuf := initialFrame
	var PDUS []units.PDU

	for protocol != units.UNKNOWN {
		parser := ParserFromProtocol(protocol)
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
