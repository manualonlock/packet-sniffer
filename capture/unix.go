package capture

import (
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

type ifReq struct {
	name  [syscall.IFNAMSIZ]byte
	index int32
}

// converts the network byte order to the host byte order
func NTOHS(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

type UnixCapturer struct {
	sock int // socket file descriptor
}

func (us *UnixCapturer) createSock() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(NTOHS(syscall.ETH_P_ALL)))
	if err != nil {
		return err
	}
	us.sock = fd
	return nil
}

func (us *UnixCapturer) bindToInterface(iface string) error {
	ifreq := ifReq{}
	copy(ifreq.name[:], iface)

	// The underlying syscall populates ifreq with ifindex that is needed to bind socket to an interface
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(us.sock), syscall.SIOCGIFINDEX, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return fmt.Errorf("failed to get interface index: %v", errno)
	}

	// Bind socket to an interface
	sll := syscall.SockaddrLinklayer{
		Protocol: NTOHS(syscall.ETH_P_ALL),
		Ifindex:  int(ifreq.index),
	}
	err := syscall.Bind(us.sock, &sll)
	return err
}

func (us *UnixCapturer) Capture() ([]byte, error) {
	buf := make([]byte, 65536)
	n, _, err := syscall.Recvfrom(us.sock, buf, 0)
	if err != nil {
		log.Fatalf("Failed to receive units: %v", err)
		return nil, err
	}
	return buf[:n], nil
}

func (us *UnixCapturer) Init(iface string) error {
	if err := us.createSock(); err != nil {
		return err
	}
	if err := us.bindToInterface(iface); err != nil {

		return err
	}
	return nil
}
