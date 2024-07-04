package main

import (
	"flag"
	"log"
	"packet_sniffer/capture"
	"packet_sniffer/parsing"
	"packet_sniffer/render"
	"packet_sniffer/utils"
	"time"
)

func terminal() {
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
			err = renderer.AddPDU(pdu)
			time.Sleep(time.Second * 2)
			if err != nil {
				log.Fatal(err)
				return
			}
		}

	}()
	renderer.Start(ifaces)

}

func stdout() {
	//parser := parsing.CompositeParser{}
	//capturer := capture.UnixCapturer{}
	//if err := capturer.Init("wlp0s20f3"); err != nil {
	//	log.Fatal(err)
	//}
	//for {
	//	var input string
	//	fmt.Println("Press enter so capture next PDU...")
	//	fmt.Scanln(&input)
	//	raw, err := capturer.Capture()
	//	if err != nil {
	//		log.Fatal(err)
	//		return
	//	}
	//	pdu, _ := parser.Parse(raw)
	//	if pdu.NextPDU != nil && pdu.NextPDU.Protocol == units.IPv4 {
	//		parsing.IPV4Parser{}.PDUBreakdown(pdu.NextPDU)
	//
	//	}
	//	fmt.Println(pdu)
	//currentPDU, err := parser.Parse(raw)

	//for currentPDU != nil {
	//	protocolHMR := units.ProtocolStringMap[currentPDU.Protocol]
	//	fmt.Printf("PDU: %s\n", protocolHMR)
	//	for h, v := range currentPDU.Headers {
	//		fmt.Printf("%s: %s\n", h, v.HumanReadableValue)
	//	}
	//	currentPDU = currentPDU.NextPDU
	//	fmt.Println()
	//}
	//	if err != nil {
	//		log.Fatal(err)
	//		return
	//	}
	//}
}

func main() {
	mode := flag.String("mode", "stdout", "Select the packet sniffer's mode")
	flag.Parse()
	if *mode == "stdout" {
		stdout()
	} else if *mode == "terminal" {
		terminal()
	}
}
