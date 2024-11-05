package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Zone represents DNS zone data
type Zone struct {
	Origin string                   `yaml:"origin"`
	SOA    map[string]interface{}   `yaml:"soa"`
	NS     []map[string]interface{} `yaml:"ns"`
	A      []map[string]interface{} `yaml:"a"`
}

// YAML Zone Provider
type YAMLZoneProvider struct {
	zones map[string]*Zone
	mu    sync.RWMutex
}

func NewYAMLZoneProvider() *YAMLZoneProvider {
	return &YAMLZoneProvider{
		zones: make(map[string]*Zone),
	}
}

func (p *YAMLZoneProvider) GetZone(name string) (*Zone, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if zone, ok := p.zones[name]; ok {
		return zone, nil
	}
	return nil, fmt.Errorf("zone not found: %s", name)
}

func (p *YAMLZoneProvider) Reload() error {
	files, err := filepath.Glob("zones/*.yml")
	if err != nil {
		return fmt.Errorf("failed to glob zone files: %v", err)
	}

	newZones := make(map[string]*Zone)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read zone file %s: %v", file, err)
		}

		var zone Zone
		if err := yaml.Unmarshal(data, &zone); err != nil {
			return fmt.Errorf("failed to unmarshal zone file %s: %v", file, err)
		}

		// zone.SOA["serial"] = generateSOASerial()
		newZones[zone.Origin] = &zone
	}

	p.mu.Lock()
	p.zones = newZones
	p.mu.Unlock()

	return nil
}

// DNS Query Structures
type Query struct {
	Header   Header
	Question Question
	Answers  []Answer
}

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
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    string
}

// Types and Constants
type QType uint16

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

var (
	zoneData = make(map[string]*Zone)
	qTypes   = []string{
		"unknown",
		"a",
		"ns",
		"md",
		"mf",
		"cname",
		"soa",
		"mb",
		"mg",
		"mr",
		"null",
		"wks",
		"ptr",
		"hinfo",
		"minfo",
		"mx",
		"txt",
	}
)

// Interfaces
type DNSHandler interface {
	Handle(msg *Query) (*Query, error)
}

type ZoneProvider interface {
	GetZone(domain string) (*Zone, error)
	Reload() error
}

type QueryEncoder interface {
	Encode(msg *Query) ([]byte, error)
}

type QueryDecoder interface {
	Decode(data []byte) (*Query, error)
}

// Handler factory
type HandlerFactory struct {
	zoneProvider ZoneProvider
	handlers     map[QType]DNSHandler
	mu           sync.RWMutex
}

func NewHandlerFactory(zp ZoneProvider) *HandlerFactory {
	hf := &HandlerFactory{
		zoneProvider: zp,
		handlers:     make(map[QType]DNSHandler),
	}
	hf.Register(TypeA, NewARecordHandler(zp))
	return hf
}

func (hf *HandlerFactory) Register(qtype QType, handler DNSHandler) {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	hf.handlers[qtype] = handler
}

func (hf *HandlerFactory) GetHandler(qtype QType) DNSHandler {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	if handler, ok := hf.handlers[qtype]; ok {
		return handler
	}
	return NewUnknownHandler()
}

// Record Handlers
type ARecordHandler struct {
	zoneProvider ZoneProvider
}

func NewARecordHandler(zp ZoneProvider) *ARecordHandler {
	return &ARecordHandler{zoneProvider: zp}
}

func (h *ARecordHandler) Handle(query *Query) (*Query, error) {
	zone, err := h.zoneProvider.GetZone(query.Question.DomainName)
	if err != nil {
		return query, err
	}

	query.Header.QR = 1 // Query or Response flag
	query.Header.AA = 1 // Authoritative Answer flag
	query.Header.ANCount = uint16(len(zone.A))

	for _, record := range zone.A {

		answer := Answer{
			Name:     []byte(query.Question.DomainName),
			Type:     uint16(TypeA),
			Class:    1,
			TTL:      uint32(record["ttl"].(int)),
			RDLength: uint16(len(record["value"].(string))),
			RData:    record["value"].(string),
		}
		query.Answers = append(query.Answers, answer)
	}
	return query, nil
}

type UnknownHandler struct{}

func NewUnknownHandler() *UnknownHandler {
	return &UnknownHandler{}
}

func (h *UnknownHandler) Handle(query *Query) (*Query, error) {
	query.Header.RCODE = 4 // Not implemented
	return query, nil
}

// Message Encoder/Decoder
type DefaultQueryEncoder struct{}

func (e *DefaultQueryEncoder) Encode(query *Query) ([]byte, error) {
	var res []byte
	// Encode header
	headerBytes := make([]byte, 12)

	flags := uint16(query.Header.QR<<15 | query.Header.Opcode<<11 | query.Header.AA<<10 |
		query.Header.TC<<9 | query.Header.RD<<8 | query.Header.RA<<7 | query.Header.Z<<4 | query.Header.RCODE)
	binary.BigEndian.PutUint16(headerBytes[0:], query.Header.ID)
	binary.BigEndian.PutUint16(headerBytes[2:], flags)
	binary.BigEndian.PutUint16(headerBytes[4:], query.Header.QDCount)
	binary.BigEndian.PutUint16(headerBytes[6:], query.Header.ANCount)
	binary.BigEndian.PutUint16(headerBytes[8:], query.Header.NSCount)
	binary.BigEndian.PutUint16(headerBytes[10:], query.Header.ARCount)
	res = append(res, headerBytes...)

	// Encode question
	qname, err := EncodeDomainName(query.Question.DomainName)
	if err != nil {
		return nil, err
	}

	qt := make([]byte, 2)
	binary.BigEndian.PutUint16(qt, uint16(query.Question.QType))
	qc := make([]byte, 2)
	binary.BigEndian.PutUint16(qc, query.Question.QClass)

	res = append(res, qname...)
	res = append(res, qt...)
	res = append(res, qc...)

	// Encode answers
	for _, ans := range query.Answers {
		answerBytes := encodeAnswer(ans)
		res = append(res, answerBytes...)
	}

	return res, nil
}

// encode domain name in DNS wire format
func EncodeDomainName(domain string) ([]byte, error) {
	if domain == "" || domain == "." {
		return []byte{0}, nil
	}
	var domainBytes bytes.Buffer
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		length := len(part)
		if length > 63 {
			return nil, fmt.Errorf("label exceeds maximum length of 63 octets")
		}
		// Add length octet
		domainBytes.WriteByte(byte(length))
		// Add label
		domainBytes.WriteString(part)
	}
	// Add terminating zero octet for root label
	domainBytes.WriteByte(0)
	return domainBytes.Bytes(), nil
}

func encodeAnswer(answer Answer) []byte {
	var answerBytes []byte
	name := make([]byte, 2)
	binary.BigEndian.PutUint16(name, uint16(0xC00C))
	answerBytes = append(answerBytes, name...)

	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, answer.Type)
	answerBytes = append(answerBytes, typ...)

	class := make([]byte, 2)
	binary.BigEndian.PutUint16(class, answer.Class)
	answerBytes = append(answerBytes, class...)

	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, answer.TTL)
	answerBytes = append(answerBytes, ttl...)

	rdlength := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlength, answer.RDLength)
	answerBytes = append(answerBytes, rdlength...)
	answerBytes = append(answerBytes, answer.RData...)

	return answerBytes
}

type (
	DefaultQueryDecoder struct{}
)

func (d *DefaultQueryDecoder) Decode(data []byte) (*Query, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("message too short")
	}
	header, err := decodeHeader(data[:12])
	if err != nil {
		return nil, err
	}
	question, err := decodeQuestion(data[12:])
	if err != nil {
		return nil, err
	}
	return &Query{
		Header:   *header,
		Question: *question,
	}, nil
}

func decodeHeader(data []byte) (*Header, error) {
	var header Header
	header.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	header.QDCount = binary.BigEndian.Uint16(data[4:6])
	header.ANCount = binary.BigEndian.Uint16(data[6:8])
	header.NSCount = binary.BigEndian.Uint16(data[8:10])
	header.ARCount = binary.BigEndian.Uint16(data[10:12])

	header.QR = flags >> 15
	header.Opcode = flags >> 11 & 0xF
	header.AA = flags >> 10 & 0x1
	header.TC = flags >> 9 & 0x1
	header.RD = flags >> 8 & 0x1
	header.RA = flags >> 7 & 0x1
	header.Z = flags >> 4 & 0x7
	header.RCODE = flags & 0xF
	return &header, nil
}

func decodeQuestion(data []byte) (*Question, error) {
	var question Question
	var domainName string
	i := 0
	for data[i] != 0 {
		length := int(data[i])
		domainName += string(data[i+1:i+1+length]) + "."
		i += length + 1
	}
	question.DomainName = domainName
	question.QType = QType(binary.BigEndian.Uint16(data[i+1 : i+3]))
	question.QClass = binary.BigEndian.Uint16(data[i+3 : i+5])
	return &question, nil
}

func DecodeDomainName(data []byte) (string, error) {
	if data[0] == 0 {
		return ".", nil
	}
	i := 0
	var domainName string
	for data[i] != 0 {
		length := int(data[i])
		domainName += string(data[i+1:i+1+length]) + "."
		i += length + 1
	}
	return domainName, nil
}

// Server
type Server struct {
	addr           string
	handlerFactory *HandlerFactory
	encoder        QueryEncoder
	decoder        QueryDecoder
}

func NewServer(addr string, handlerFactory *HandlerFactory, encoder QueryEncoder, decoder QueryDecoder) *Server {
	return &Server{
		addr:           addr,
		handlerFactory: handlerFactory,
		encoder:        encoder,
		decoder:        decoder,
	}
}

func (s *Server) Run() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	defer conn.Close()
	log.Printf("DNS Server listening on %s", s.addr)
	return s.serve(conn)
}

func (s *Server) serve(conn *net.UDPConn) error {
	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}
		go s.handleRequest(conn, *remoteAddr, buffer[:n])
	}
}

func (s *Server) handleRequest(conn *net.UDPConn, remoteAddr net.UDPAddr, data []byte) {
	query, err := s.decoder.Decode(data)
	if err != nil {
		log.Printf("Error decoding message: %v", err)
		return
	}
	handler := s.handlerFactory.GetHandler(query.Question.QType)
	response, err := handler.Handle(query)
	if err != nil {
		log.Printf("Error handling message: %v", err)
		return
	}

	resData, err := s.encoder.Encode(response)
	if err != nil {
		log.Printf("Error encoding response: %v", err)
		return
	}
	if _, err := conn.WriteToUDP(resData, &remoteAddr); err != nil {
		log.Printf("Error sending response: %v", err)
		return
	}
}

func loadZones() error {
	files, err := filepath.Glob("zones/*.yml")
	if err != nil {
		return fmt.Errorf("failed to glob zone files: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read zone file %s: %v", file, err)
		}

		var zone Zone
		if err := yaml.Unmarshal(data, &zone); err != nil {
			return fmt.Errorf("failed to unmarshal zone file %s: %v", file, err)
		}

		zoneData[zone.Origin] = &zone
	}
	return nil
}

func main() {
	// if err := loadZones(); err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Println(zoneData)
	// for k, v := range zoneData {
	// 	fmt.Println(k, v)
	// }

	// Create dependencies
	zoneProvider := NewYAMLZoneProvider()
	if err := zoneProvider.Reload(); err != nil {
		log.Fatalf("Failed to load zones: %v", err)
	}

	handlerFactory := NewHandlerFactory(zoneProvider)
	encoder := &DefaultQueryEncoder{}
	decoder := &DefaultQueryDecoder{}

	// Create and run server
	server := NewServer(":53153", handlerFactory, encoder, decoder)
	if err := server.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
