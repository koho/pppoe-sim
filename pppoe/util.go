package pppoe

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
)

type Option interface {
	Content() []byte
	Len() int
}

func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func UInt16ToBytes(a uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, a)
	return b
}

func GetTimeString() string {
	t := time.Now()
	h, m, s := t.Clock()
	ms := t.Nanosecond() / int(time.Millisecond)
	return fmt.Sprintf("%02d:%02d:%02d.%03d", h, m, s, ms)
}
