package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DNS header size
const hSize = 12

type ARecord struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
	TTL   uint32 `yaml:"ttl"`
}

// Zone represents DNS zone data
type Zone struct {
	SOA    map[string]interface{}   `yaml:"soa"`
	Origin string                   `yaml:"origin"`
	NS     []map[string]interface{} `yaml:"ns"`
	A      []ARecord                `yaml:"a"`
	TTL    int                      `yaml:"ttl"`
}

var (
	zones     = make(map[string]Zone)
	blocklist = make(map[string]bool)
)

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func loadZones() {
	files, err := filepath.Glob("zones/*.yml")
	check(err)
	for _, file := range files {
		data, err := os.ReadFile(file)
		check(err)
		zone := Zone{}
		yaml.Unmarshal(data, &zone)
		name := zone.Origin
		zones[name] = zone
	}
	fmt.Printf("%+v\n", zones)
}

// DNS Message Structure
type Message struct {
	Bytes    []byte
	Question Question
	Answers  []Answer
	Header   Header
}

// 16bits used for bit shifting
type Header struct {
	ID      uint16
	QR      uint16 // Query/Response flag (false=query, true=response)
	Opcode  uint16 // Operation code
	AA      uint16 // Authoritative Answer flag
	TC      uint16 // Truncated flag
	RD      uint16 // Recursion Desired flag
	RA      uint16 // Recursion Available flag
	Z       uint16 // Reserved for future use
	RCODE   uint16 // Response code
	QDCount uint16 // Question count
	ANCount uint16 // Answer count
	NSCount uint16 // Name servers count
	ARCount uint16 // Authority count
}

// DNSQuestion represents a question in the DNS message
type Question struct {
	DomainName string
	QType      QType
	QClass     uint16
}

type Answer struct {
	RData    []byte
	Name     []byte
	TTL      uint32
	Type     uint16
	Class    uint16
	RDLength uint16
}

// QType represents DNS query type
type QType uint16

// qtype enum
const (
	TypeA     QType = 1
	TypeNS    QType = 2
	TypeMD    QType = 3
	TypeMF    QType = 4
	TypeCNAME QType = 5
	TypeSOA   QType = 6
	TypeMB    QType = 7
	TypeMG    QType = 8
	TypeMR    QType = 9
	TypeNULL  QType = 10
	TypeWKS   QType = 11
	TypePTR   QType = 12
	TypeHINFO QType = 13
	TypeMINFO QType = 14
	TypeMX    QType = 15
	TypeTXT   QType = 16
)

var types = map[QType]string{
	TypeA:     "a",
	TypeNS:    "ns",
	TypeMD:    "md",
	TypeMF:    "mf",
	TypeCNAME: "cname",
	TypeSOA:   "soa",
	TypeMB:    "mb",
	TypeMG:    "mg",
	TypeMR:    "mr",
	TypeNULL:  "null",
	TypeWKS:   "wks",
	TypePTR:   "ptr",
	TypeHINFO: "hinfo",
	TypeMINFO: "minfo",
	TypeMX:    "mx",
	TypeTXT:   "txt",
}

type DomainName string

// encode domain name to dns wire format
func EncodeDomainName(dn string) ([]byte, error) {
	if dn == "" || dn == "." {
		return []byte{0}, nil
	}
	bytes := bytes.Buffer{}
	dn = strings.TrimSuffix(dn, ".")
	parts := strings.Split(dn, ".")
	for _, part := range parts {
		if len(part) > 63 {
			return nil, errors.New("label exceeds maximum length of 63 octets")
		}

		bytes.WriteByte(byte(len(part)))
		bytes.WriteString(part)
	}
	bytes.WriteByte(0)
	return bytes.Bytes(), nil
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

type Encoder interface {
	Encode() []byte
}

func (header *Header) Encode() []byte {
	headerBytes := make([]byte, hSize)
	// Encoding logic here
	flags := uint16(header.QR<<15 | header.Opcode<<11 | header.AA<<10 | header.TC<<9 | header.RD<<8 | header.RA<<7 | header.Z<<4 | header.RCODE)

	binary.BigEndian.PutUint16(headerBytes, header.ID)
	binary.BigEndian.PutUint16(headerBytes[2:], flags)
	binary.BigEndian.PutUint16(headerBytes[4:], header.QDCount)
	binary.BigEndian.PutUint16(headerBytes[6:], header.ANCount)
	binary.BigEndian.PutUint16(headerBytes[8:], header.NSCount)
	binary.BigEndian.PutUint16(headerBytes[10:], header.ARCount)
	log.Println("header id: ", header.ID)
	log.Println("headerBytes: ", headerBytes)
	return headerBytes
}

func (question *Question) Encode() []byte {
	var questionBytes []byte
	// Encoding logic here
	dn, err := EncodeDomainName(question.DomainName)
	if err != nil {
		return nil
	}
	temp16 := make([]byte, 2)
	questionBytes = append(questionBytes, dn...)
	binary.BigEndian.PutUint16(temp16, uint16(question.QType))
	questionBytes = append(questionBytes, temp16...)
	binary.BigEndian.PutUint16(temp16, uint16(question.QClass))
	questionBytes = append(questionBytes, temp16...)
	return questionBytes
}

func encodeIP(ip string) []byte {
	ipBytes := net.ParseIP(ip)
	if ipBytes == nil {
		return nil
	}
	return ipBytes.To4()
}

func (answer *Answer) Encode(msg *Message) []byte {
	var answerBytes []byte
	// Encoding logic here

	temp16 := make([]byte, 2)
	temp32 := make([]byte, 4)
	answerBytes = append(answerBytes, answer.Name...)
	binary.BigEndian.PutUint16(temp16, answer.Type)
	answerBytes = append(answerBytes, temp16...)
	binary.BigEndian.PutUint16(temp16, answer.Class)
	answerBytes = append(answerBytes, temp16...)
	binary.BigEndian.PutUint32(temp32, answer.TTL)
	answerBytes = append(answerBytes, temp32...)
	binary.BigEndian.PutUint16(temp16, answer.RDLength)
	answerBytes = append(answerBytes, temp16...)
	answerBytes = append(answerBytes, answer.RData...)
	return answerBytes
}

func (msg *Message) Encode() []byte {
	var msgBytes []byte
	// Encoding logic here
	return msgBytes
}

type Decoder interface {
	Decode(data []byte)
}

func (header *Header) Decode(data []byte) error {
	header.ID = binary.BigEndian.Uint16(data[0:2])
	header.QR = binary.BigEndian.Uint16(data[2:4]) >> 15
	header.Opcode = (binary.BigEndian.Uint16(data[2:4]) >> 11) & 0x0F
	header.AA = (binary.BigEndian.Uint16(data[2:4]) >> 10) & 0x01
	header.TC = (binary.BigEndian.Uint16(data[2:4]) >> 9) & 0x01
	header.RD = (binary.BigEndian.Uint16(data[2:4]) >> 8) & 0x01
	header.RA = (binary.BigEndian.Uint16(data[2:4]) >> 7) & 0x01
	header.Z = (binary.BigEndian.Uint16(data[2:4]) >> 4) & 0x07
	header.RCODE = binary.BigEndian.Uint16(data[2:4]) & 0x0F
	header.QDCount = binary.BigEndian.Uint16(data[4:6])
	header.ANCount = binary.BigEndian.Uint16(data[6:8])
	header.NSCount = binary.BigEndian.Uint16(data[8:10])
	header.ARCount = binary.BigEndian.Uint16(data[10:12])
	log.Println(header)
	return nil
}

func (question *Question) Decode(data []byte) (int, error) {
	var qOffset int
	dn, qOffset, err := DecodeDomainName(data)
	if err != nil {
		return 0, err
	}
	question.DomainName = dn
	question.QType = QType(binary.BigEndian.Uint16(data[qOffset : qOffset+2]))
	question.QClass = binary.BigEndian.Uint16(data[qOffset+2 : qOffset+4])
	return qOffset, nil
}

func (msg *Message) Decode(data []byte) (int, error) {
	// Decoding logic here
	err := msg.Header.Decode(data[:hSize])
	qOffset, err := msg.Question.Decode(data[hSize:])
	if err != nil {
		return 0, err
	}
	mSize := qOffset + hSize
	return mSize, nil
}

type Server struct {
	address string
}

func NewServer(address string) *Server {
	return &Server{
		address: address,
	}
}

func (s *Server) Run() {
	buffer := make([]byte, 512)
	udpAddr, err := net.ResolveUDPAddr("udp", s.address)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("DNS Server running on ", s.address)
	defer conn.Close()
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Received", n, "bytes")
		log.Println("from: ", remoteAddr)
		go s.handle(conn, remoteAddr, buffer[:n])
	}
}

func Proxy(data []byte, publicDNS string) []byte {
	res := make([]byte, 512)

	// Resolve the string address to a UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", publicDNS)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Dial to the address with UDP
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send a message to the server
	_, err = conn.Write(data)
	fmt.Println("send...")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// Read from the connection into the buffer
	_, err = bufio.NewReader(conn).Read(res)
	if err != nil {
		log.Println(err)
		return res
	}
	fmt.Println("read...")
	return res
}

func (msg *Message) Lookup(nameServer string) []byte {
	res := Proxy(msg.Bytes, nameServer)
	message := Message{}
	message.Decode(res)
	fmt.Printf("message: %+v\n", message)
	return res
}

func (msg *Message) BuildResponse() []byte {
	var res []byte
	var answers []byte

	zone := zones[msg.Question.DomainName]
	fmt.Println("zone: ", zone)
	fmt.Printf("%+v\n", zone)
	fmt.Println("blocklist: ", blocklist[msg.Question.DomainName])
	if blocklist[msg.Question.DomainName] {

		msg.Header.ARCount = 0
		msg.Header.QR = 1
		msg.Header.ANCount = 1

		answer := Answer{}

		// TODO: check if record.Name is "@"...
		name, err := EncodeDomainName(msg.Question.DomainName)
		if err != nil {
			return nil
		}
		answer.Name = name
		answer.Type = uint16(msg.Question.QType)
		answer.Class = uint16(msg.Question.QClass)
		// answer.TTL = record.TTL
		answer.TTL = uint32(0)
		answer.RData = encodeIP("127.0.0.1")
		answer.RDLength = uint16(len(answer.RData))
		msg.Answers = append(msg.Answers, answer)
	} else if zone.Origin == "" && !blocklist[msg.Question.DomainName] {
		fmt.Println("zone not found")

		nameServer := "198.41.0.4" + ":53"
		// googleDNS := "8.8.8.8:53"
		// cloudflareDNS := "1.1.1.1:53"
		// return Proxy(msg.Bytes, googleDNS)
		return msg.Lookup(nameServer)
	} else if zone.Origin != "" && !blocklist[msg.Question.DomainName] {
		switch msg.Question.QType {
		case TypeA:
			for _, record := range zone.A {
				answer := Answer{}

				// TODO: check if record.Name is "@"...
				name, err := EncodeDomainName(msg.Question.DomainName)
				if err != nil {
					return nil
				}
				answer.Name = name
				answer.Type = uint16(msg.Question.QType)
				answer.Class = uint16(msg.Question.QClass)
				// answer.TTL = record.TTL
				answer.TTL = uint32(0)
				answer.RData = encodeIP(record.Value)
				answer.RDLength = uint16(len(answer.RData))
				msg.Answers = append(msg.Answers, answer)
			}
		default:
		}

		msg.Header.ARCount = 0
		msg.Header.QR = 1
		msg.Header.ANCount = uint16(len(msg.Answers))
	}

	res = append(res, msg.Header.Encode()...)
	res = append(res, msg.Question.Encode()...)

	for _, answer := range msg.Answers {
		answers = append(answers, answer.Encode(msg)...)
	}
	res = append(res, answers...)
	return res
}

func (s *Server) handle(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	// log.Println(data)
	msg := Message{}
	msg.Bytes = data
	_, err := msg.Decode(data)
	if err != nil {
		log.Println(err)
		return
	}
	res := msg.BuildResponse()
	conn.WriteToUDP(res, remoteAddr)
}

func main() {
	loadZones()
	// loadBlocklist()
	blocklist["google.com."] = true
	server := NewServer(
		"127.0.0.1:53153",
	)
	server.Run()
}
