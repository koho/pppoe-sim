package pppoe

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

type PPPLCPCode byte

const (
	PPPLCPCodeConfigurationRequest PPPLCPCode = 0x1
	PPPLCPCodeConfigurationAck     PPPLCPCode = 0x2
	PPPLCPCodeConfigurationNak     PPPLCPCode = 0x3
	PPPLCPCodeConfigurationReject  PPPLCPCode = 0x4
	PPPLCPCodeTerminateRequest     PPPLCPCode = 0x5
	PPPLCPCodeTerminateAck         PPPLCPCode = 0x6
	PPPLCPCodeCodeReject           PPPLCPCode = 0x7
	PPPLCPCodeProtocolReject       PPPLCPCode = 0x8
	PPPLCPCodeEchoRequest          PPPLCPCode = 0x9
	PPPLCPCodeEchoReply            PPPLCPCode = 0xa
	PPPLCPCodeDiscardRequest       PPPLCPCode = 0xb
	PPPLCPCodeIdentification       PPPLCPCode = 0xc
	PPPLCPCodeTimeRemaining        PPPLCPCode = 0xd
)

type PPPLCP struct {
	Code       PPPLCPCode
	Identifier byte
	Length     uint16
	Options    []Option
	Payload    []byte
}

var LayerTypePPPLCP = gopacket.RegisterLayerType(
	2001,
	gopacket.LayerTypeMetadata{
		"LayerTypePPPLCP",
		gopacket.DecodeFunc(nil),
	},
)

func (m *PPPLCP) Content() []byte {
	content := make([]byte, 0)
	content = append(content, byte(m.Code))
	content = append(content, m.Identifier)
	content = append(content, UInt16ToBytes(m.Length)...)
	for _, op := range m.Options {
		content = append(content, op.Content()...)
	}
	return content
}

func (m *PPPLCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(m.Code)
	bytes, err = b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = m.Identifier

	bytes, err = b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, m.Length)
	for _, op := range m.Options {
		bytes, err = b.AppendBytes(op.Len())
		if err != nil {
			return err
		}
		copy(bytes, op.Content())
	}
	return nil
}

func (m *PPPLCP) LayerType() gopacket.LayerType {
	return LayerTypePPPLCP
}

type PPPLCPOptionType byte

const (
	PPPLCPOptionTypeMRU                               PPPLCPOptionType = 0x1
	PPPLCPOptionTypeAuthenticationProtocol            PPPLCPOptionType = 0x3
	PPPLCPOptionTypeQualityProtocol                   PPPLCPOptionType = 0x4
	PPPLCPOptionTypeMagicNumber                       PPPLCPOptionType = 0x5
	PPPLCPOptionTypeProtocolFieldCompression          PPPLCPOptionType = 0x7
	PPPLCPOptionTypeAddressAndControlFieldCompression PPPLCPOptionType = 0x8
	PPPLCPOptionTypeIdentification                    PPPLCPOptionType = 0xc
	PPPLCPOptionTypeCallback                          PPPLCPOptionType = 0xd
)

type PPPLCPOption struct {
	Type   PPPLCPOptionType
	Length byte
	Data   []byte
}

func (m *PPPLCPOption) Len() int {
	return 2 + len(m.Data)
}

func (m *PPPLCPOption) Content() []byte {
	content := make([]byte, 0)
	content = append(content, byte(m.Type))
	content = append(content, m.Length)
	content = append(content, m.Data...)
	return content
}

type PPPLCPEchoOption struct {
	Magic uint32
	Data  []byte
}

func (m *PPPLCPEchoOption) Len() int {
	return 4 + len(m.Data)
}

func (m *PPPLCPEchoOption) Content() []byte {
	content := make([]byte, 4)
	binary.BigEndian.PutUint32(content, m.Magic)
	content = append(content, m.Data...)
	return content
}

type PPPLCPTerminateOption struct {
	Data []byte
}

func (m *PPPLCPTerminateOption) Len() int {
	return len(m.Data)
}

func (m *PPPLCPTerminateOption) Content() []byte {
	return m.Data
}

func FindLCPOption(options []Option, optionType PPPLCPOptionType) *PPPLCPOption {
	for _, op := range options {
		if pppOp, ok := op.(*PPPLCPOption); ok && pppOp.Type == optionType {
			return pppOp
		}
	}
	return nil
}

func DecodePPPLCPOptions(data []byte) []Option {
	options := make([]Option, 0)
	for i := 0; i < len(data); {
		op := PPPLCPOption{PPPLCPOptionType(data[i]), data[i+1], data[(i + 2):(i + 2 + int(data[i+1]) - 2)]}
		options = append(options, &op)
		i += op.Len()
	}
	return options
}

func DecodeEchoLCPOptions(data []byte) []Option {
	rest := make([]byte, 0)
	if len(data) > 4 {
		rest = data[4:]
	}
	return []Option{&PPPLCPEchoOption{Magic: binary.BigEndian.Uint32(data[:4]), Data: rest}}
}

func DecodeTerminateLCPOptions(data []byte) []Option {
	return []Option{&PPPLCPTerminateOption{Data: data}}
}

func (m *PPPLCP) DecodeFromBytes(data []byte) {
	m.Code = PPPLCPCode(data[0])
	m.Identifier = data[1]
	m.Length = binary.BigEndian.Uint16(data[2:4])
	switch m.Code {
	case PPPLCPCodeEchoRequest:
	case PPPLCPCodeEchoReply:
		m.Options = DecodeEchoLCPOptions(data[4:m.Length])
	case PPPLCPCodeTerminateRequest:
		m.Options = DecodeTerminateLCPOptions(data[4:m.Length])
	default:
		m.Options = DecodePPPLCPOptions(data[4:m.Length])
	}

	optionsLen := 0
	for _, op := range m.Options {
		optionsLen += op.Len()
	}
	rest := 4 + optionsLen
	if rest >= len(data) {
		m.Payload = make([]byte, 0)
	} else {
		m.Payload = data[(4 + optionsLen):]
	}
}

func sendLCP(dst net.HardwareAddr, code PPPLCPCode, sid uint16, id byte, options []Option) {
	pppLayer := layers.PPP{}
	pppLayer.PPPType = PPPTypeLCP

	optionsLen := 0
	for _, op := range options {
		optionsLen += op.Len()
	}

	buffer := gopacket.NewSerializeBuffer()
	so := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, so,
		&layers.PPP{
			PPPType: PPPTypeLCP,
		},
		&PPPLCP{
			Code:       code,
			Identifier: id,
			Length:     uint16(4 + optionsLen),
			Options:    options,
		},
	)
	sendPacket(dst, buffer.Bytes(), layers.PPPoECodeSession, sid, layers.EthernetTypePPPoESession, uint16(len(buffer.Bytes())))
}
