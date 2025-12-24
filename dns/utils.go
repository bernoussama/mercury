package dns

import (
	"bytes"
	"errors"
	"strings"
)

type DomainName string

// encode domain name to dns wire format
func EncodeDomainName(dn string) ([]byte, error) {
	if dn == "" || dn == "." {
		return []byte{0}, nil
	}
	dn = strings.TrimSuffix(dn, ".")
	var buf bytes.Buffer
	buf.Grow(len(dn) + 2)
	parts := strings.Split(dn, ".")
	for _, part := range parts {
		if len(part) > 63 {
			return nil, errors.New("label exceeds maximum length of 63 octets")
		}

		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0)
	return buf.Bytes(), nil
}

func DecodeDomainName(data []byte) (string, int, error) {
	if len(data) == 1 && data[0] == 0 {
		return ".", 0, nil
	}
	var dn string
	i := 0
	for data[i] != 0 {
		length := int(data[i])
		if i+length >= len(data) {
			return "", 0, errors.New("invalid domain name")
		}
		dn += string(data[i+1:i+1+length]) + "."
		i += length + 1
	}
	return dn, i + 1, nil
}

type Encoder[T any] interface {
	Encode() []byte
}
