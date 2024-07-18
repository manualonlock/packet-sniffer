package utils

import (
	"fmt"
	units "packet_sniffer/model"
	"packet_sniffer/parsing"
)

func PDUPrettyPrint(pdu *units.PDU) {
	currentPDU := pdu
	for currentPDU != nil {
		fmt.Printf("Protocol: %s\n", units.ProtocolStringMap[currentPDU.Protocol].Full)
		fmt.Println("Headers:")
		parser := parsing.ParserFromProtocol(currentPDU.Protocol)
		for k, _ := range currentPDU.Headers {
			fmt.Printf("%s: %s\n", parser.HeaderName(k), parser.HeaderToHumanReadable(k, currentPDU))
		}
		fmt.Println()
		currentPDU = currentPDU.NextPDU
	}
	fmt.Println()
	fmt.Println()
}
