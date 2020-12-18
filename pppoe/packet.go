package pppoe

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"net"
	"reflect"
	"time"
)

const (
	PPPTypeLCP                     layers.PPPType = 0xc021
	PPPTypePasswordAuthentication  layers.PPPType = 0xc023
	PPPTypeChallengeAuthentication layers.PPPType = 0xc223
	PPPTypeIPCP                    layers.PPPType = 0x8021
	PPPTypeIPV6CP                  layers.PPPType = 0x8057
)

const incomingFormat = "%s [%s <- %s] [%s] %s\n"
const outgoingFormat = "%s [%s -> %s] [%s] %s\n"

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle

	ifMac net.HardwareAddr
)

func sendPacket(dst net.HardwareAddr, payload []byte, code layers.PPPoECode, sid uint16, protocol layers.EthernetType, length uint16) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       ifMac,
			DstMAC:       dst,
			EthernetType: protocol,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      code,
			SessionId: sid,
			Length:    length,
		},
		gopacket.Payload(payload),
	)
	handle.WritePacketData(buffer.Bytes())
}

func ServePPPoE(iface *Interface) (string, string, error) {
	ifMac = iface.HardwareAddr
	var username = ""
	var password = ""
	// Open device
	handle, err = pcap.OpenLive(iface.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		return "", "", err
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			continue
		}
		ethernet, _ := ethernetLayer.(*layers.Ethernet)
		if reflect.DeepEqual(ethernet.SrcMAC, net.HardwareAddr{0xE0, 0xD5, 0x5E, 0x47, 0xFF, 0x4C}) {
			continue
		}
		pppoeLayer := packet.Layer(layers.LayerTypePPPoE)
		if pppoeLayer != nil {
			pppoe, _ := pppoeLayer.(*layers.PPPoE)
			switch pppoe.Code {
			case layers.PPPoECodePADI:
				fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPPoED", "Active Discovery Initiation (PADI)")
				sendPADO(ethernet.SrcMAC, []PPPoETag{
					{TagNameHostUniq, GenerateRandomBytes(8)},
					{TagNameACName, "Simulator"},
					{TagNameACCookie, GenerateRandomBytes(16)},
				})
				fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPPoED", "Active Discovery Offer (PADO)")
			case layers.PPPoECodePADR:
				fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPPoED", "Active Discovery Request (PADR)")
				sendPADS(ethernet.SrcMAC, pppoe.Payload)
				fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPPoED", "Active Discovery Session-confirmation (PADS)")
			case layers.PPPoECodeSession:
				pppLayer := packet.Layer(layers.LayerTypePPP)
				if pppLayer != nil {
					ppp, _ := pppLayer.(*layers.PPP)
					switch ppp.PPPType {
					case PPPTypeLCP:
						var lcpLayer PPPLCP
						lcpLayer.DecodeFromBytes(ppp.Payload)
						switch lcpLayer.Code {
						case PPPLCPCodeConfigurationRequest:
							fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPP LCP", "Configuration Request")
							sendLCP(ethernet.SrcMAC, PPPLCPCodeConfigurationAck, pppoe.SessionId, lcpLayer.Identifier, lcpLayer.Options)
							fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPP LCP", "Configuration Ack")
							var mru = []byte{0x05, 0xd4}
							mruOption := FindLCPOption(lcpLayer.Options, PPPLCPOptionTypeMRU)
							if mruOption != nil {
								mru = mruOption.Data
							}
							sendLCP(ethernet.SrcMAC, PPPLCPCodeConfigurationRequest, pppoe.SessionId, lcpLayer.Identifier+1, []Option{
								&PPPLCPOption{PPPLCPOptionTypeMRU, 4, mru},
								&PPPLCPOption{PPPLCPOptionTypeAuthenticationProtocol, 4, UInt16ToBytes(uint16(PPPTypePasswordAuthentication))},
								&PPPLCPOption{PPPLCPOptionTypeMagicNumber, 6, GenerateRandomBytes(4)},
							})
							fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPP LCP", "Configuration Request")
						case PPPLCPCodeConfigurationAck:
							fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPP LCP", "Configuration Ack")
						case PPPLCPCodeConfigurationReject:
							fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPP LCP", "Configuration Reject")
						case PPPLCPCodeEchoRequest:
							fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPP LCP", "Echo Request")
							sendLCP(ethernet.SrcMAC, PPPLCPCodeEchoReply, pppoe.SessionId, lcpLayer.Identifier, []Option{
								&PPPLCPEchoOption{rand.Uint32(), make([]byte, 0)},
							})
							fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPP LCP", "Echo Reply")
						case PPPLCPCodeTerminateRequest:
							fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPP LCP", "Termination Request")
							sendLCP(ethernet.SrcMAC, PPPLCPCodeTerminateAck, pppoe.SessionId, lcpLayer.Identifier, []Option{
								&PPPLCPTerminateOption{Data: make([]byte, 0)},
							})
							fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPP LCP", "Termination Ack")
						}
					case PPPTypePasswordAuthentication:
						var passwdLayer PPPPasswdAuthentication
						passwdLayer.DecodeFromBytes(ppp.Payload)
						switch passwdLayer.Code {
						case AuthenticateRequest:
							fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPP PAP", "Authenticate-Request")
							authOption := passwdLayer.Options[0].(*PPPPasswdAuthRequestOption)
							username = string(authOption.PeerId)
							password = string(authOption.Passwd)
							sendPPPPasswdAuthentication(ethernet.SrcMAC, AuthenticateACK, pppoe.SessionId, passwdLayer.Identifier, []Option{
								&PPPPasswdAuthResultOption{MessageLength: 0, Message: make([]byte, 0)},
							})
							fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPP PAP", "Authenticate-Ack")
						}
					case PPPTypeIPCP:
					case PPPTypeIPV6CP:
						fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPP LCP", "Termination Request")
						sendLCP(ethernet.SrcMAC, PPPLCPCodeTerminateRequest, pppoe.SessionId, 1, []Option{
							&PPPLCPTerminateOption{Data: make([]byte, 0)},
						})
						fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPPoED", "Active Discovery Terminate (PADT)")
						sendPADT(ethernet.SrcMAC, make([]byte, 0))
						return username, password, nil
					}
				}
			case layers.PPPoECodePADT:
				fmt.Printf(incomingFormat, GetTimeString(), ethernet.DstMAC, ethernet.SrcMAC, "PPPoED", "Active Discovery Terminate (PADT)")
				sendPADT(ethernet.SrcMAC, pppoe.Payload)
				fmt.Printf(outgoingFormat, GetTimeString(), ifMac, ethernet.SrcMAC, "PPPoED", "Active Discovery Terminate (PADT)")
			}
		}
	}
	return username, password, nil
}
