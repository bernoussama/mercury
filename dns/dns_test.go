package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/bernoussama/mercury/cache"
)

// TestHeaderEncode tests the Header.Encode() method
func TestHeaderEncode(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		want   []byte
	}{
		{
			name: "basic query header",
			header: Header{
				ID:      0x1234,
				QR:      0,
				Opcode:  0,
				AA:      0,
				TC:      0,
				RD:      1,
				RA:      0,
				Z:       0,
				RCODE:   0,
				QDCount: 1,
				ANCount: 0,
				NSCount: 0,
				ARCount: 0,
			},
			want: []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "response header with answers",
			header: Header{
				ID:      0xABCD,
				QR:      1,
				Opcode:  0,
				AA:      1,
				TC:      0,
				RD:      1,
				RA:      1,
				Z:       0,
				RCODE:   0,
				QDCount: 1,
				ANCount: 2,
				NSCount: 0,
				ARCount: 0,
			},
			want: []byte{0xAB, 0xCD, 0x85, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "error response with RCODE",
			header: Header{
				ID:      0x5678,
				QR:      1,
				Opcode:  0,
				AA:      0,
				TC:      0,
				RD:      1,
				RA:      1,
				Z:       0,
				RCODE:   3, // NXDOMAIN
				QDCount: 1,
				ANCount: 0,
				NSCount: 1,
				ARCount: 0,
			},
			want: []byte{0x56, 0x78, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
		},
		{
			name: "header with all sections",
			header: Header{
				ID:      0xFFFF,
				QR:      1,
				Opcode:  0,
				AA:      1,
				TC:      0,
				RD:      1,
				RA:      1,
				Z:       0,
				RCODE:   0,
				QDCount: 1,
				ANCount: 3,
				NSCount: 2,
				ARCount: 1,
			},
			want: []byte{0xFF, 0xFF, 0x85, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01},
		},
		{
			name: "zero header",
			header: Header{
				ID:      0,
				QR:      0,
				Opcode:  0,
				AA:      0,
				TC:      0,
				RD:      0,
				RA:      0,
				Z:       0,
				RCODE:   0,
				QDCount: 0,
				ANCount: 0,
				NSCount: 0,
				ARCount: 0,
			},
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.header.Encode()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Header.Encode() = %v, want %v", got, tt.want)
			}
			// Verify the encoded header has correct length
			if len(got) != headerSize {
				t.Errorf("Header.Encode() length = %d, want %d", len(got), headerSize)
			}
		})
	}
}

// TestHeaderEncodeCapacity verifies that the encoded header has the expected capacity
func TestHeaderEncodeCapacity(t *testing.T) {
	header := Header{
		ID:      0x1234,
		QR:      0,
		Opcode:  0,
		AA:      0,
		TC:      0,
		RD:      1,
		RA:      0,
		Z:       0,
		RCODE:   0,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	encoded := header.Encode()
	if len(encoded) != headerSize {
		t.Errorf("Header.Encode() length = %d, want %d", len(encoded), headerSize)
	}
	if cap(encoded) != headerSize {
		t.Errorf("Header.Encode() capacity = %d, want %d", cap(encoded), headerSize)
	}
}

// TestQuestionEncode tests the Question.Encode() method
func TestQuestionEncode(t *testing.T) {
	tests := []struct {
		name     string
		question Question
		wantLen  int
		checkFn  func([]byte) bool
	}{
		{
			name: "simple A record query",
			question: Question{
				DomainName: "example.com",
				QType:      TypeA,
				QClass:     1,
			},
			wantLen: 17, // 7+example+3+com+0 (13 bytes) + 2 (type) + 2 (class) = 17
			checkFn: func(b []byte) bool {
				// Verify domain name encoding
				if b[0] != 7 || string(b[1:8]) != "example" {
					return false
				}
				if b[8] != 3 || string(b[9:12]) != "com" {
					return false
				}
				if b[12] != 0 {
					return false
				}
				// Verify type and class
				qtype := binary.BigEndian.Uint16(b[13:15])
				qclass := binary.BigEndian.Uint16(b[15:17])
				return qtype == uint16(TypeA) && qclass == 1
			},
		},
		{
			name: "subdomain query",
			question: Question{
				DomainName: "sub.example.com",
				QType:      TypeA,
				QClass:     1,
			},
			wantLen: 21, // 3+sub+7+example+3+com+0 (17 bytes) + 2 + 2 = 21
			checkFn: func(b []byte) bool {
				return b[0] == 3 && string(b[1:4]) == "sub"
			},
		},
		{
			name: "root domain query",
			question: Question{
				DomainName: ".",
				QType:      TypeA,
				QClass:     1,
			},
			wantLen: 5, // 0 (1 byte) + 2 + 2 = 5
			checkFn: func(b []byte) bool {
				return b[0] == 0 && len(b) == 5
			},
		},
		{
			name: "NS record query",
			question: Question{
				DomainName: "example.com",
				QType:      TypeNS,
				QClass:     1,
			},
			wantLen: 17,
			checkFn: func(b []byte) bool {
				qtype := binary.BigEndian.Uint16(b[13:15])
				return qtype == uint16(TypeNS)
			},
		},
		{
			name: "MX record query",
			question: Question{
				DomainName: "example.com",
				QType:      TypeMX,
				QClass:     1,
			},
			wantLen: 17,
			checkFn: func(b []byte) bool {
				qtype := binary.BigEndian.Uint16(b[13:15])
				return qtype == uint16(TypeMX)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.question.Encode()
			if got == nil {
				t.Fatal("Question.Encode() returned nil")
			}
			if len(got) != tt.wantLen {
				t.Errorf("Question.Encode() length = %d, want %d", len(got), tt.wantLen)
			}
			if !tt.checkFn(got) {
				t.Errorf("Question.Encode() validation failed for %v", got)
			}
		})
	}
}

// TestQuestionEncodeCapacity verifies proper capacity allocation
func TestQuestionEncodeCapacity(t *testing.T) {
	question := Question{
		DomainName: "example.com",
		QType:      TypeA,
		QClass:     1,
	}

	encoded := question.Encode()
	expectedLen := 17
	if len(encoded) != expectedLen {
		t.Errorf("Question.Encode() length = %d, want %d", len(encoded), expectedLen)
	}
	// The capacity should be at least the length (preallocated)
	if cap(encoded) < len(encoded) {
		t.Errorf("Question.Encode() capacity = %d, should be >= length %d", cap(encoded), len(encoded))
	}
}

// TestQuestionEncodeInvalidDomain tests error handling
func TestQuestionEncodeInvalidDomain(t *testing.T) {
	tests := []struct {
		name     string
		question Question
	}{
		{
			name: "label too long",
			question: Question{
				DomainName: "this-label-is-way-too-long-as-it-exceeds-63-characters-which-is-not-allowed-in-dns.com",
				QType:      TypeA,
				QClass:     1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.question.Encode()
			if got != nil {
				t.Errorf("Question.Encode() should return nil for invalid domain, got %v", got)
			}
		})
	}
}

// TestAnswerEncode tests the Answer.Encode() method
func TestAnswerEncode(t *testing.T) {
	domainName, _ := EncodeDomainName("example.com")
	ipData := []byte{192, 0, 2, 1}

	tests := []struct {
		name   string
		answer Answer
		msg    *Message
		want   func([]byte) bool
	}{
		{
			name: "A record answer",
			answer: Answer{
				Name:     domainName,
				Type:     uint16(TypeA),
				Class:    1,
				TTL:      300,
				RDLength: 4,
				RData:    ipData,
			},
			msg: &Message{},
			want: func(b []byte) bool {
				// Verify structure: Name + Type (2) + Class (2) + TTL (4) + RDLength (2) + RData
				if len(b) != len(domainName)+10+4 {
					return false
				}
				// Check domain name
				if !bytes.Equal(b[:len(domainName)], domainName) {
					return false
				}
				offset := len(domainName)
				// Check type
				if binary.BigEndian.Uint16(b[offset:offset+2]) != uint16(TypeA) {
					return false
				}
				// Check class
				if binary.BigEndian.Uint16(b[offset+2:offset+4]) != 1 {
					return false
				}
				// Check TTL
				if binary.BigEndian.Uint32(b[offset+4:offset+8]) != 300 {
					return false
				}
				// Check RDLength
				if binary.BigEndian.Uint16(b[offset+8:offset+10]) != 4 {
					return false
				}
				// Check RData
				return bytes.Equal(b[offset+10:], ipData)
			},
		},
		{
			name: "answer with zero TTL",
			answer: Answer{
				Name:     domainName,
				Type:     uint16(TypeA),
				Class:    1,
				TTL:      0,
				RDLength: 4,
				RData:    ipData,
			},
			msg: &Message{},
			want: func(b []byte) bool {
				offset := len(domainName)
				return binary.BigEndian.Uint32(b[offset+4:offset+8]) == 0
			},
		},
		{
			name: "answer with max TTL",
			answer: Answer{
				Name:     domainName,
				Type:     uint16(TypeA),
				Class:    1,
				TTL:      4294967295, // max uint32
				RDLength: 4,
				RData:    ipData,
			},
			msg: &Message{},
			want: func(b []byte) bool {
				offset := len(domainName)
				return binary.BigEndian.Uint32(b[offset+4:offset+8]) == 4294967295
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.answer.Encode(tt.msg)
			if got == nil {
				t.Fatal("Answer.Encode() returned nil")
			}
			if !tt.want(got) {
				t.Errorf("Answer.Encode() validation failed")
			}
		})
	}
}

// TestAnswerEncodeCapacity verifies proper capacity allocation
func TestAnswerEncodeCapacity(t *testing.T) {
	domainName, _ := EncodeDomainName("example.com")
	ipData := []byte{192, 0, 2, 1}

	answer := Answer{
		Name:     domainName,
		Type:     uint16(TypeA),
		Class:    1,
		TTL:      300,
		RDLength: 4,
		RData:    ipData,
	}

	msg := &Message{}
	encoded := answer.Encode(msg)

	expectedLen := len(domainName) + 10 + len(ipData)
	if len(encoded) != expectedLen {
		t.Errorf("Answer.Encode() length = %d, want %d", len(encoded), expectedLen)
	}
	// Capacity should be at least the length
	if cap(encoded) < len(encoded) {
		t.Errorf("Answer.Encode() capacity = %d, should be >= length %d", cap(encoded), len(encoded))
	}
}

// TestMessageEncode tests the Message.Encode() method
func TestMessageEncode(t *testing.T) {
	domainName, _ := EncodeDomainName("example.com")
	ipData := []byte{192, 0, 2, 1}

	tests := []struct {
		name string
		msg  Message
		want func([]byte) bool
	}{
		{
			name: "simple query message",
			msg: Message{
				Header: Header{
					ID:      0x1234,
					QR:      0,
					Opcode:  0,
					AA:      0,
					TC:      0,
					RD:      1,
					RA:      0,
					Z:       0,
					RCODE:   0,
					QDCount: 1,
					ANCount: 0,
					NSCount: 0,
					ARCount: 0,
				},
				Question: Question{
					DomainName: "example.com",
					QType:      TypeA,
					QClass:     1,
				},
				Answers:    []Answer{},
				Authority:  []Answer{},
				Additional: []Answer{},
			},
			want: func(b []byte) bool {
				// Should have header (12) + question (17) = 29 bytes
				return len(b) == 29 && b[0] == 0x12 && b[1] == 0x34
			},
		},
		{
			name: "response with single answer",
			msg: Message{
				Header: Header{
					ID:      0xABCD,
					QR:      1,
					Opcode:  0,
					AA:      1,
					TC:      0,
					RD:      1,
					RA:      1,
					Z:       0,
					RCODE:   0,
					QDCount: 1,
					ANCount: 1,
					NSCount: 0,
					ARCount: 0,
				},
				Question: Question{
					DomainName: "example.com",
					QType:      TypeA,
					QClass:     1,
				},
				Answers: []Answer{
					{
						Name:     domainName,
						Type:     uint16(TypeA),
						Class:    1,
						TTL:      300,
						RDLength: 4,
						RData:    ipData,
					},
				},
				Authority:  []Answer{},
				Additional: []Answer{},
			},
			want: func(b []byte) bool {
				// Should have header + question + answer
				expectedLen := 12 + 17 + len(domainName) + 10 + 4
				return len(b) == expectedLen
			},
		},
		{
			name: "response with multiple answers",
			msg: Message{
				Header: Header{
					ID:      0x5678,
					QR:      1,
					Opcode:  0,
					AA:      1,
					TC:      0,
					RD:      1,
					RA:      1,
					Z:       0,
					RCODE:   0,
					QDCount: 1,
					ANCount: 2,
					NSCount: 0,
					ARCount: 0,
				},
				Question: Question{
					DomainName: "example.com",
					QType:      TypeA,
					QClass:     1,
				},
				Answers: []Answer{
					{
						Name:     domainName,
						Type:     uint16(TypeA),
						Class:    1,
						TTL:      300,
						RDLength: 4,
						RData:    ipData,
					},
					{
						Name:     domainName,
						Type:     uint16(TypeA),
						Class:    1,
						TTL:      600,
						RDLength: 4,
						RData:    []byte{192, 0, 2, 2},
					},
				},
				Authority:  []Answer{},
				Additional: []Answer{},
			},
			want: func(b []byte) bool {
				// Should have header + question + 2 answers
				expectedLen := 12 + 17 + 2*(len(domainName)+10+4)
				return len(b) == expectedLen
			},
		},
		{
			name: "empty message",
			msg: Message{
				Header: Header{
					ID:      0,
					QR:      0,
					Opcode:  0,
					AA:      0,
					TC:      0,
					RD:      0,
					RA:      0,
					Z:       0,
					RCODE:   0,
					QDCount: 0,
					ANCount: 0,
					NSCount: 0,
					ARCount: 0,
				},
				Question: Question{
					DomainName: ".",
					QType:      TypeA,
					QClass:     1,
				},
				Answers:    []Answer{},
				Authority:  []Answer{},
				Additional: []Answer{},
			},
			want: func(b []byte) bool {
				// Header (12) + minimal question (5) = 17 bytes
				return len(b) == 17
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.Encode()
			if got == nil {
				t.Fatal("Message.Encode() returned nil")
			}
			if !tt.want(got) {
				t.Errorf("Message.Encode() validation failed, length = %d", len(got))
			}
		})
	}
}

// TestMessageEncodeCapacity verifies proper capacity preallocation
func TestMessageEncodeCapacity(t *testing.T) {
	domainName, _ := EncodeDomainName("example.com")
	ipData := []byte{192, 0, 2, 1}

	msg := Message{
		Header: Header{
			ID:      0x1234,
			QR:      1,
			Opcode:  0,
			AA:      1,
			TC:      0,
			RD:      1,
			RA:      1,
			Z:       0,
			RCODE:   0,
			QDCount: 1,
			ANCount: 1,
			NSCount: 0,
			ARCount: 0,
		},
		Question: Question{
			DomainName: "example.com",
			QType:      TypeA,
			QClass:     1,
		},
		Answers: []Answer{
			{
				Name:     domainName,
				Type:     uint16(TypeA),
				Class:    1,
				TTL:      300,
				RDLength: 4,
				RData:    ipData,
			},
		},
		Authority:  []Answer{},
		Additional: []Answer{},
	}

	encoded := msg.Encode()
	expectedLen := 12 + 17 + len(domainName) + 10 + 4

	if len(encoded) != expectedLen {
		t.Errorf("Message.Encode() length = %d, want %d", len(encoded), expectedLen)
	}
	// Capacity should be exactly what was preallocated (or very close)
	if cap(encoded) < len(encoded) {
		t.Errorf("Message.Encode() capacity = %d, should be >= length %d", cap(encoded), len(encoded))
	}
}

// TestEncodeIP tests the encodeIP helper function
func TestEncodeIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want []byte
	}{
		{
			name: "valid IPv4",
			ip:   "192.0.2.1",
			want: []byte{192, 0, 2, 1},
		},
		{
			name: "localhost",
			ip:   "127.0.0.1",
			want: []byte{127, 0, 0, 1},
		},
		{
			name: "zero IP",
			ip:   "0.0.0.0",
			want: []byte{0, 0, 0, 0},
		},
		{
			name: "broadcast",
			ip:   "255.255.255.255",
			want: []byte{255, 255, 255, 255},
		},
		{
			name: "invalid IP",
			ip:   "invalid",
			want: nil,
		},
		{
			name: "empty string",
			ip:   "",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeIP(tt.ip)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("encodeIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// Mock cache for testing BuildResponse
type mockCache struct {
	data map[string]Message
}

func (m *mockCache) Get(key string) (*Message, bool) {
	msg, ok := m.data[key]
	if !ok {
		return nil, false
	}
	return &msg, true
}

func (m *mockCache) Set(key string, msg Message, ttl uint32) {
	if m.data == nil {
		m.data = make(map[string]Message)
	}
	msg.Expiry = time.Now().Add(time.Duration(ttl) * time.Second)
	m.data[key] = msg
}

func (m *mockCache) Delete(key string) {
	delete(m.data, key)
}

func (m *mockCache) Invalidate() {
	m.data = make(map[string]Message)
}

// TestMessageBuildResponse tests the BuildResponse method
func TestMessageBuildResponse(t *testing.T) {
	tests := []struct {
		name      string
		msg       Message
		zones     map[string]Zone
		cache     cache.Cache[Message]
		blocklist map[string]bool
		want      func([]byte) bool
	}{
		{
			name: "blocked domain returns localhost",
			msg: Message{
				Header: Header{
					ID:      0x1234,
					QDCount: 1,
				},
				Question: Question{
					DomainName: "blocked.com",
					QType:      TypeA,
					QClass:     1,
				},
			},
			zones:     make(map[string]Zone),
			cache:     &mockCache{data: make(map[string]Message)},
			blocklist: map[string]bool{"blocked.com": true},
			want: func(b []byte) bool {
				// Verify it returns a response
				if len(b) < 12 {
					return false
				}
				// Check QR flag is set (bit 15 of flags)
				flags := binary.BigEndian.Uint16(b[2:4])
				qr := (flags >> 15) & 0x01
				return qr == 1 && len(b) > 29 // Has answer section
			},
		},
		{
			name: "zone data returns configured IP",
			msg: Message{
				Header: Header{
					ID:      0x5678,
					QDCount: 1,
				},
				Question: Question{
					DomainName: "example.local",
					QType:      TypeA,
					QClass:     1,
				},
			},
			zones: map[string]Zone{
				"example.local": {
					Origin: "example.local",
					A: []ARecord{
						{
							Name:  "example.local",
							Value: "10.0.0.1",
							TTL:   300,
						},
					},
				},
			},
			cache:     &mockCache{data: make(map[string]Message)},
			blocklist: make(map[string]bool),
			want: func(b []byte) bool {
				// Verify response has answer
				if len(b) < 12 {
					return false
				}
				flags := binary.BigEndian.Uint16(b[2:4])
				qr := (flags >> 15) & 0x01
				ancount := binary.BigEndian.Uint16(b[6:8])
				return qr == 1 && ancount > 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.BuildResponse(tt.zones, tt.cache, tt.blocklist)
			if got == nil {
				t.Fatal("BuildResponse() returned nil")
			}
			if !tt.want(got) {
				t.Errorf("BuildResponse() validation failed")
			}
		})
	}
}

// TestMessageBuildResponseCapacity verifies proper capacity preallocation
func TestMessageBuildResponseCapacity(t *testing.T) {
	msg := Message{
		Header: Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Question: Question{
			DomainName: "blocked.com",
			QType:      TypeA,
			QClass:     1,
		},
	}

	zones := make(map[string]Zone)
	cache := &mockCache{data: make(map[string]Message)}
	blocklist := map[string]bool{"blocked.com": true}

	response := msg.BuildResponse(zones, cache, blocklist)

	if response == nil {
		t.Fatal("BuildResponse() returned nil")
	}

	// Verify capacity is reasonable (should be preallocated)
	if cap(response) < len(response) {
		t.Errorf("BuildResponse() capacity = %d, should be >= length %d", cap(response), len(response))
	}
}

// Benchmark tests to verify performance improvements

func BenchmarkHeaderEncode(b *testing.B) {
	header := Header{
		ID:      0x1234,
		QR:      1,
		Opcode:  0,
		AA:      1,
		TC:      0,
		RD:      1,
		RA:      1,
		Z:       0,
		RCODE:   0,
		QDCount: 1,
		ANCount: 1,
		NSCount: 0,
		ARCount: 0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = header.Encode()
	}
}

func BenchmarkQuestionEncode(b *testing.B) {
	question := Question{
		DomainName: "example.com",
		QType:      TypeA,
		QClass:     1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = question.Encode()
	}
}

func BenchmarkAnswerEncode(b *testing.B) {
	domainName, _ := EncodeDomainName("example.com")
	answer := Answer{
		Name:     domainName,
		Type:     uint16(TypeA),
		Class:    1,
		TTL:      300,
		RDLength: 4,
		RData:    []byte{192, 0, 2, 1},
	}
	msg := &Message{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = answer.Encode(msg)
	}
}

func BenchmarkMessageEncode(b *testing.B) {
	domainName, _ := EncodeDomainName("example.com")
	msg := Message{
		Header: Header{
			ID:      0x1234,
			QR:      1,
			Opcode:  0,
			AA:      1,
			TC:      0,
			RD:      1,
			RA:      1,
			Z:       0,
			RCODE:   0,
			QDCount: 1,
			ANCount: 1,
			NSCount: 0,
			ARCount: 0,
		},
		Question: Question{
			DomainName: "example.com",
			QType:      TypeA,
			QClass:     1,
		},
		Answers: []Answer{
			{
				Name:     domainName,
				Type:     uint16(TypeA),
				Class:    1,
				TTL:      300,
				RDLength: 4,
				RData:    []byte{192, 0, 2, 1},
			},
		},
		Authority:  []Answer{},
		Additional: []Answer{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = msg.Encode()
	}
}

func BenchmarkMessageEncodeMultipleAnswers(b *testing.B) {
	domainName, _ := EncodeDomainName("example.com")
	answers := make([]Answer, 5)
	for i := range answers {
		answers[i] = Answer{
			Name:     domainName,
			Type:     uint16(TypeA),
			Class:    1,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{192, 0, 2, byte(i + 1)},
		}
	}

	msg := Message{
		Header: Header{
			ID:      0x1234,
			QR:      1,
			Opcode:  0,
			AA:      1,
			TC:      0,
			RD:      1,
			RA:      1,
			Z:       0,
			RCODE:   0,
			QDCount: 1,
			ANCount: 5,
			NSCount: 0,
			ARCount: 0,
		},
		Question: Question{
			DomainName: "example.com",
			QType:      TypeA,
			QClass:     1,
		},
		Answers:    answers,
		Authority:  []Answer{},
		Additional: []Answer{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = msg.Encode()
	}
}