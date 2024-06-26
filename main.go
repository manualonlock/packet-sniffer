package main

import (
	"flag"
	"fmt"
	"log"
	"packet_sniffer/capture"
	units "packet_sniffer/model"
	"packet_sniffer/parsing"
	"packet_sniffer/render"
	"packet_sniffer/services"
	"time"
)

func terminal() {
	renderer := render.TerminalRenderer{}
	renderer.Init()
	parser := services.Parser{
		EthernetParser: &parsing.EthernetParser{},
		IPv4Parser:     &parsing.IPV4Parser{},
	}
	capturer := capture.UnixCapturer{}
	if err := capturer.Init("wlp0s20f3"); err != nil {
		log.Fatal(err)
	}

	go func() {
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

	renderer.Run()
}

func stdout() {
	parser := services.Parser{
		EthernetParser: &parsing.EthernetParser{},
		IPv4Parser:     &parsing.IPV4Parser{},
	}
	capturer := capture.UnixCapturer{}
	if err := capturer.Init("wlp0s20f3"); err != nil {
		log.Fatal(err)
	}
	for {
		var input string
		fmt.Println("Press enter so capture next PDU...")
		fmt.Scanln(&input)
		raw, err := capturer.Capture()
		if err != nil {
			log.Fatal(err)
			return
		}
		currentPDU, err := parser.Parse(raw)

		for currentPDU != nil {
			protocolHMR := units.ProtocolStringMap[currentPDU.Protocol]
			fmt.Printf("PDU: %s\n", protocolHMR)
			for h, v := range currentPDU.Headers {
				fmt.Printf("%s: %s\n", h, v.HumanReadableValue)
			}
			currentPDU = currentPDU.NextPDU
			fmt.Println()
		}
		if err != nil {
			log.Fatal(err)
			return
		}
	}
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
