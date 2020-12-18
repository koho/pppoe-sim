package pppoe

import (
	"github.com/google/gopacket/layers"
	"net"
)

type TagName uint16

const (
	TagNameServiceName TagName = 0x0101
	TagNameACName      TagName = 0x0102
	TagNameHostUniq    TagName = 0x0103
	TagNameACCookie    TagName = 0x0104
)

type PPPoETag struct {
	TagName  TagName
	TagValue interface{}
}

func PPPoETags(tags []PPPoETag) []byte {
	payload := make([]byte, 0)
	payload = append(payload, []byte{1, 1, 0, 0}...)
	for _, tag := range tags {
		payload = append(payload, UInt16ToBytes(uint16(tag.TagName))...)
		if tagStr, ok := tag.TagValue.(string); ok {
			payload = append(payload, UInt16ToBytes(uint16(len(tagStr)))...)
			payload = append(payload, []byte(tagStr)...)
		} else if tagByte, ok := tag.TagValue.([]byte); ok {
			payload = append(payload, UInt16ToBytes(uint16(len(tagByte)))...)
			payload = append(payload, tagByte...)
		}
	}
	return payload
}

func sendPADO(dst net.HardwareAddr, tags []PPPoETag) {
	pppoeTags := PPPoETags(tags)
	sendPacket(dst, pppoeTags, layers.PPPoECodePADO, 0, layers.EthernetTypePPPoEDiscovery, uint16(len(pppoeTags)))
}

func sendPADS(dst net.HardwareAddr, tags []byte) {
	sendPacket(dst, tags, layers.PPPoECodePADS, 1, layers.EthernetTypePPPoEDiscovery, uint16(len(tags)))
}

func sendPADT(dst net.HardwareAddr, tags []byte) {
	sendPacket(dst, tags, layers.PPPoECodePADT, 1, layers.EthernetTypePPPoEDiscovery, uint16(len(tags)))
}
