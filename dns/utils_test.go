package dns

import (
	"bytes"
	"testing"
)

func TestEncodeDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		errMsg  string
		want    []byte
		wantErr bool
	}{
		{
			name:    "simple domain",
			input:   "example.com",
			want:    []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr: false,
		},
		{
			name:    "subdomain",
			input:   "sub.example.com",
			want:    []byte{3, 's', 'u', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   ".",
			want:    []byte{0},
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    []byte{0},
			wantErr: false,
		},
		{
			name:    "trailing dot",
			input:   "example.com.",
			want:    []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr: false,
		},
		{
			name:    "single label",
			input:   "localhost",
			want:    []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0},
			wantErr: false,
		},
		{
			name:  "long label",
			input: "test.really-loong-subdomain-label-that-is-exactly-63-characters-long.com",
			want:  append(append(append([]byte{4, 't', 'e', 's', 't'}, append([]byte{63}, []byte("really-loong-subdomain-label-that-is-exactly-63-characters-long")...)...), append([]byte{3}, []byte("com")...)...), []byte{0}...),

			// want: []byte{4, 116, 101, 115, 116, 62, 114, 101, 97, 108, 108, 121, 45, 108, 111, 110, 103, 45, 115, 117, 98, 100, 111, 109, 97, 105, 110, 45, 108, 97, 98, 101, 108, 45, 116, 104, 97, 116, 45, 105, 115, 45, 101, 120, 97, 99, 116, 108, 121, 45, 54, 51, 45, 99, 104, 97, 114, 97, 99, 116, 101, 114, 115, 45, 108, 111, 110, 103, 3, 99, 111, 109, 0}
			wantErr: false,
		},
		{
			name:    "label too long",
			input:   "test.this-label-is-way-too-long-as-it-exceeds-63-characters-which-is-not-allowed-in-dns.com",
			wantErr: true,
			errMsg:  "label exceeds maximum length of 63 octets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeDomainName(tt.input)

			// Check error cases
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil || err.Error() != tt.errMsg {
					t.Errorf("EncodeDomain() error = %v, want error message %v", err, tt.errMsg)
				}
				return
			}

			// Check result
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeDomain(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		errMsg  string
		input   []byte
		wantErr bool
	}{
		{
			name:    "simple domain",
			want:    "example.com.",
			input:   []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr: false,
		},
		{
			name:    "subdomain",
			want:    "sub.example.com.",
			input:   []byte{3, 's', 'u', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr: false,
		},
		{
			name:    "root domain",
			want:    ".",
			input:   []byte{0},
			wantErr: false,
		},
		{
			name:    "trailing dot",
			want:    "example.com.",
			input:   []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr: false,
		},
		{
			name:    "single label",
			want:    "localhost.",
			input:   []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := DecodeDomainName(tt.input)

			// Check error cases
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil || err.Error() != tt.errMsg {
					t.Errorf("EncodeDomain() error = %v, want error message %v", err, tt.errMsg)
				}
				return
			}

			// Check result
			if got != tt.want {
				t.Errorf("EncodeDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEncodeDomainNameCapacity verifies that the buffer is properly preallocated
func TestEncodeDomainNameCapacity(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		minCapacity    int
		checkCapacity  bool
	}{
		{
			name:          "simple domain",
			input:         "example.com",
			minCapacity:   15, // len("example.com") + 2
			checkCapacity: true,
		},
		{
			name:          "subdomain",
			input:         "sub.example.com",
			minCapacity:   19, // len("sub.example.com") + 2
			checkCapacity: true,
		},
		{
			name:          "long domain",
			input:         "very.long.subdomain.example.com",
			minCapacity:   35, // len + 2
			checkCapacity: true,
		},
		{
			name:          "single label",
			input:         "localhost",
			minCapacity:   11, // len("localhost") + 2
			checkCapacity: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeDomainName(tt.input)
			if err != nil {
				t.Fatalf("EncodeDomainName() unexpected error = %v", err)
			}
			
			// The capacity should be at least what we expect from the preallocated buffer
			if tt.checkCapacity && cap(got) < tt.minCapacity {
				t.Errorf("EncodeDomainName() capacity = %d, want >= %d", cap(got), tt.minCapacity)
			}

			// Verify the length is correct
			if len(got) < 1 {
				t.Errorf("EncodeDomainName() returned empty slice")
			}
		})
	}
}

// TestEncodeDomainNameMultipleCalls verifies consistency across multiple calls
func TestEncodeDomainNameMultipleCalls(t *testing.T) {
	domain := "example.com"
	
	// Encode the same domain multiple times
	results := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		result, err := EncodeDomainName(domain)
		if err != nil {
			t.Fatalf("EncodeDomainName() error on iteration %d: %v", i, err)
		}
		results[i] = result
	}

	// Verify all results are identical
	expected := results[0]
	for i := 1; i < 100; i++ {
		if !bytes.Equal(results[i], expected) {
			t.Errorf("EncodeDomainName() iteration %d = %v, want %v", i, results[i], expected)
		}
	}
}

// TestEncodeDomainNameEdgeCases tests various edge cases
func TestEncodeDomainNameEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "multiple trailing dots",
			input:   "example.com...",
			wantErr: false, // Should trim trailing dots
		},
		{
			name:    "domain with hyphen",
			input:   "my-domain.com",
			wantErr: false,
		},
		{
			name:    "domain with numbers",
			input:   "example123.com",
			wantErr: false,
		},
		{
			name:    "deeply nested subdomain",
			input:   "a.b.c.d.e.f.example.com",
			wantErr: false,
		},
		{
			name:    "single character labels",
			input:   "a.b.c",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeDomainName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeDomainName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("EncodeDomainName() returned nil for valid input")
			}
		})
	}
}

// TestDecodeDomainNameEdgeCases tests edge cases for decoding
func TestDecodeDomainNameEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantLen int
	}{
		{
			name:    "multiple labels",
			input:   []byte{1, 'a', 1, 'b', 1, 'c', 0},
			wantErr: false,
			wantLen: 7,
		},
		{
			name:    "max length label",
			input:   append(append([]byte{63}, bytes.Repeat([]byte{'a'}, 63)...), 0),
			wantErr: false,
			wantLen: 65,
		},
		{
			name:    "invalid - label length exceeds data",
			input:   []byte{100, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, offset, err := DecodeDomainName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeDomainName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == "" {
					t.Errorf("DecodeDomainName() returned empty string")
				}
				if tt.wantLen > 0 && offset != tt.wantLen {
					t.Errorf("DecodeDomainName() offset = %d, want %d", offset, tt.wantLen)
				}
			}
		})
	}
}

// TestEncodeDecodeRoundtrip tests that encoding and decoding are inverse operations
func TestEncodeDecodeRoundtrip(t *testing.T) {
	tests := []string{
		"example.com",
		"sub.example.com",
		"a.b.c.d.e.f.example.com",
		"localhost",
		"my-domain.com",
		"example123.com",
	}

	for _, domain := range tests {
		t.Run(domain, func(t *testing.T) {
			// Encode
			encoded, err := EncodeDomainName(domain)
			if err != nil {
				t.Fatalf("EncodeDomainName() error = %v", err)
			}

			// Decode
			decoded, _, err := DecodeDomainName(encoded)
			if err != nil {
				t.Fatalf("DecodeDomainName() error = %v", err)
			}

			// Compare (decoded will have trailing dot)
			expectedDecoded := domain
			if !bytes.HasSuffix([]byte(domain), []byte{'.'}) {
				expectedDecoded = domain + "."
			}

			if decoded != expectedDecoded {
				t.Errorf("Roundtrip failed: got %q, want %q", decoded, expectedDecoded)
			}
		})
	}
}

// Benchmark tests to measure performance improvements

func BenchmarkEncodeDomainName(b *testing.B) {
	domain := "example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeDomainName(domain)
	}
}

func BenchmarkEncodeDomainNameLong(b *testing.B) {
	domain := "very.long.subdomain.with.many.labels.example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeDomainName(domain)
	}
}

func BenchmarkEncodeDomainNameShort(b *testing.B) {
	domain := "a.b"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeDomainName(domain)
	}
}

func BenchmarkDecodeDomainName(b *testing.B) {
	encoded := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DecodeDomainName(encoded)
	}
}

func BenchmarkEncodeDecodeRoundtrip(b *testing.B) {
	domain := "example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, _ := EncodeDomainName(domain)
		_, _, _ = DecodeDomainName(encoded)
	}
}
