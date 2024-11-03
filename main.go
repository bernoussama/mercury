package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Zone represents DNS zone data
type Zone struct {
	Origin string                   `yaml:"origin"`
	SOA    map[string]interface{}   `yaml:"soa"`
	NS     []map[string]interface{} `yaml:"ns"`
	A      []map[string]interface{} `yaml:"a"`
}

type DNSHeader struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCODE   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion represents a question in the DNS message
type DNSQuestion struct {
	DomainName string
	QType      uint16
	QClass     uint16
}

type DNSAnswer struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    string
}

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
