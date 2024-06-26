package utils

import "net"

func GetNetworkInterfaces() []string {
	ifaces, _ := net.Interfaces()
	output := make([]string, len(ifaces))
	for i, iface := range ifaces {
		output[i] = iface.Name
	}
	return output
}
