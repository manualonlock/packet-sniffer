package parsing

import (
	units "packet_sniffer/model"
)

type Parser interface {
	Parse(buf []byte) (*units.PDU, error)
	GetNextProtocol(pdu *units.PDU) units.Protocol
}
