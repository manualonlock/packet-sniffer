package parsing

import units "packet_sniffer/model"

// Derived structs that implement Parser must have their Src/Dest headers come first as below
const (
	SRCHeader units.PDUHeaderKey = iota
	DSTHeader
)
