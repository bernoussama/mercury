package main

import (
	"bytes"
	"testing"
)

func TestEncodeDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
		errMsg  string
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
		input   []byte
		wantErr bool
		errMsg  string
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
			got, err := DecodeDomainName(tt.input)

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
