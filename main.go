package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"packet_sniffer/capture"
	units "packet_sniffer/model"
	"packet_sniffer/parsing"
	"packet_sniffer/render"
	"packet_sniffer/utils"
	"strconv"
	"strings"
)

func isMakingThroughFilter(pdu *units.PDU, protocols []units.Protocol) bool {
	currentPDU := pdu
	for currentPDU != nil {
		for _, protocol := range protocols {
			if protocol == currentPDU.Protocol {
				return true
			}
		}
		currentPDU = currentPDU.NextPDU
	}
	return false
}

func terminal(protocols []units.Protocol) {
	parser := parsing.CompositeParser{}
	capturer := capture.UnixCapturer{}

	networkInterface := make(chan string)

	renderer := render.Terminal{NetworkInterface: networkInterface}

	ifaces := utils.GetNetworkInterfaces()
	go func() {
		iface := <-networkInterface

		if err := capturer.Init(iface); err != nil {
			log.Fatal(err)
		}
		for {
			raw, err := capturer.Capture()
			if err != nil {
				log.Fatal(err)
				return
			}
			pdu, err := parser.Parse(raw)
			//if len(protocols) > 0 && isMakingThroughFilter(pdu, protocols) {
			//	err = renderer.AddPDU(pdu)
			//	//time.Sleep(time.Second * 2)
			//	if err != nil {
			//		log.Fatal(err)
			//		return
			//	}
			//}
			err = renderer.AddPDU(pdu)
			if err != nil {
				log.Fatal(err)
				return
			}
		}

	}()
	renderer.Start(ifaces)
}

func stdout(protocols []units.Protocol) {
	reader := bufio.NewReader(os.Stdout)

	parser := parsing.CompositeParser{}
	capturer := capture.UnixCapturer{}
	fmt.Println("Select a network interface:")
	ifaces := utils.GetNetworkInterfaces()
	for i, iface := range ifaces {
		fmt.Printf("%d: %s\n", i+1, iface)
	}
	fmt.Println()
	choice, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}
	choice = strings.TrimSpace(choice)
	option, err := strconv.Atoi(choice)
	if err != nil {
		fmt.Println(err)
		return
	}
	if option > len(ifaces) && option < 1 {
		return
	}
	capturer.Init(ifaces[option-1])

	for {
		buf, _ := capturer.Capture()
		pdu, _ := parser.Parse(buf)
		if len(protocols) > 0 && isMakingThroughFilter(pdu, protocols) {
			utils.PDUPrettyPrint(pdu)
			fmt.Println("Press enter to get the next PDU...")
			reader.ReadString('\n')
		}
	}
}

func main() {
	mode := flag.String("mode", "stdout", "Select the packet sniffer's mode")
	protocols := flag.String("protocols", "", "Comma separated list of protocol names")
	flag.Parse()

	protocolsToFilter := make([]units.Protocol, 0)
	if protocols != nil {
		for _, protocol := range strings.Split(*protocols, ",") {
			for internalProtocolCode, protocolName := range units.ProtocolStringMap {
				if strings.ToLower(protocolName.Shortened) == strings.ToLower(protocol) {
					protocolsToFilter = append(protocolsToFilter, internalProtocolCode)
				}
			}
		}
	}
	if *mode == "stdout" {
		stdout(protocolsToFilter)
	} else if *mode == "terminal" {
		terminal(protocolsToFilter)
	}
}
