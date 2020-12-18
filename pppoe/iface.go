package pppoe

import (
	"encoding/csv"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type Interface struct {
	pcap.Interface
	HardwareAddr net.HardwareAddr
}

func GetActiveInterfaces() ([]*Interface, error) {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	interfaces := make([]*Interface, 0)
	for _, d := range devices {
		interfaces = append(interfaces, &Interface{
			Interface: d,
		})
	}
	getMACAddr(interfaces)
	activeInterfaces := make([]*Interface, 0)
	for _, d := range interfaces {
		if d.HardwareAddr != nil {
			activeInterfaces = append(activeInterfaces, d)
		}
	}
	return activeInterfaces, nil
}

func getMACAddr(interfaces []*Interface) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("getmac", "/FO", "csv", "/NH").Output()
		if err != nil {
			log.Fatal(err)
		}
		macReader := csv.NewReader(strings.NewReader(string(out)))
		macRecords, _ := macReader.ReadAll()
		for _, iface := range interfaces {
			devID := iface.Name
			devIDPattern := regexp.MustCompile(`\{(.+)\}`)
			matches := devIDPattern.FindStringSubmatch(iface.Name)
			if matches != nil {
				devID = matches[1]
			}
			for _, macRow := range macRecords {
				if matches = devIDPattern.FindStringSubmatch(macRow[1]); matches != nil && matches[1] == devID {
					if mac, err := net.ParseMAC(macRow[0]); err == nil {
						iface.HardwareAddr = mac
					}
				}
			}
		}
	} else {
		ifaces, _ := net.Interfaces()
		for _, iface := range interfaces {
			for _, netInterface := range ifaces {
				if netInterface.Name == iface.Name {
					iface.HardwareAddr = netInterface.HardwareAddr
				}
			}
		}
	}
}
