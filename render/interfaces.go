package render

import units "packet_sniffer/model"

type Renderer interface {
	AddPDU(pdu *units.PDU) error
}
