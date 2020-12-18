package pppoe

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

type PPPAuthenticationCode byte

const (
	AuthenticateRequest PPPAuthenticationCode = 1
	AuthenticateACK     PPPAuthenticationCode = 2
	AuthenticationNak   PPPAuthenticationCode = 3
)

type PPPPasswdAuthRequestOption struct {
	PeerIdLength byte
	PeerId       []byte
	PasswdLength byte
	Passwd       []byte
}

func (m *PPPPasswdAuthRequestOption) Content() []byte {
	content := make([]byte, 0)
	content = append(content, m.PeerIdLength)
	content = append(content, m.PeerId...)
	content = append(content, m.PasswdLength)
	content = append(content, m.Passwd...)
	return content
}

func (m *PPPPasswdAuthRequestOption) Len() int {
	return 1 + len(m.PeerId) + 1 + len(m.Passwd)
}

func DecodePPPPasswdAuthRequestOption(data []byte) []Option {
	var option PPPPasswdAuthRequestOption
	option.PeerIdLength = data[0]
	i := 1 + option.PeerIdLength
	option.PeerId = data[1:i]
	option.PasswdLength = data[i]
	i += 1
	option.Passwd = data[i:(i + option.PasswdLength)]
	return []Option{&option}
}

type PPPPasswdAuthResultOption struct {
	MessageLength byte
	Message       []byte
}

func (m *PPPPasswdAuthResultOption) Content() []byte {
	content := make([]byte, 0)
	content = append(content, m.MessageLength)
	content = append(content, m.Message...)
	return content
}

func (m *PPPPasswdAuthResultOption) Len() int {
	return 1 + len(m.Message)
}

func DecodePPPPasswdAuthResultOption(data []byte) []Option {
	message := make([]byte, 0)
	if data[0] > 0 {
		message = data[1:(1 + data[0])]
	}
	return []Option{&PPPPasswdAuthResultOption{MessageLength: data[0], Message: message}}
}

type PPPPasswdAuthentication struct {
	Code       PPPAuthenticationCode
	Identifier byte
	Length     uint16
	Options    []Option
}

var LayerTypePPPPasswdAuthentication = gopacket.RegisterLayerType(
	2002,
	gopacket.LayerTypeMetadata{
		"LayerTypePPPPasswdAuthentication",
		gopacket.DecodeFunc(nil),
	},
)

func (m *PPPPasswdAuthentication) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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

func (m *PPPPasswdAuthentication) LayerType() gopacket.LayerType {
	return LayerTypePPPPasswdAuthentication
}

func (m *PPPPasswdAuthentication) DecodeFromBytes(data []byte) {
	m.Code = PPPAuthenticationCode(data[0])
	m.Identifier = data[1]
	m.Length = binary.BigEndian.Uint16(data[2:4])
	switch m.Code {
	case AuthenticateRequest:
		m.Options = DecodePPPPasswdAuthRequestOption(data[4:m.Length])
	case AuthenticateACK:
	case AuthenticationNak:
		m.Options = DecodePPPPasswdAuthResultOption(data[4:m.Length])
	}
}

func sendPPPPasswdAuthentication(dst net.HardwareAddr, auth PPPAuthenticationCode, sid uint16, id byte, options []Option) {
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
			PPPType: PPPTypePasswordAuthentication,
		},
		&PPPPasswdAuthentication{
			Code:       auth,
			Identifier: id,
			Length:     uint16(4 + optionsLen),
			Options:    options,
		},
	)
	sendPacket(dst, buffer.Bytes(), layers.PPPoECodeSession, sid, layers.EthernetTypePPPoESession, uint16(len(buffer.Bytes())))
}
