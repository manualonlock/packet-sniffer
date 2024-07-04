package parsing

import (
	units "packet_sniffer/model"
)

type PDUBreakdownOutput struct {
	KeyName     string
	Value       string
	Description *string
	Header      *units.Header

	InnerBreakdowns []PDUBreakdownOutput
}

type Parser interface {
	Parse(buf []byte) (*units.PDU, error)
	GetNextProtocol(pdu *units.PDU) units.Protocol
	MostSignificantHeaders() []units.PDUHeaderKey
	HeaderName(header units.PDUHeaderKey) string
	PDUBreakdown(pdu *units.PDU) []PDUBreakdownOutput
	HeaderToHumanReadable(headerKey units.PDUHeaderKey, header units.Header) string
}
