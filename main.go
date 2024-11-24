package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/bernoussama/mercury/cmd"
	"github.com/bernoussama/mercury/dns"
	"gopkg.in/yaml.v3"
)

// DNS header size
const BUFFER_SIZE = 2048

// dns sinkhole
var blocklist = make(map[string]bool)

var (
	zones    = make(map[string]dns.Zone)
	dnsCache = &dns.RecordsCache{Records: make(map[string]dns.Message)}
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
		zone := dns.Zone{}
		yaml.Unmarshal(data, &zone)
		name := zone.Origin
		zones[name] = zone
	}
	fmt.Printf("%+v\n", zones)
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
	buffer := make([]byte, BUFFER_SIZE)
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

func (s *Server) handle(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	// log.Println(data)
	msg := dns.Message{}
	msg.Bytes = data
	_, err := msg.Decode(data)
	if err != nil {
		log.Println(err)
		return
	}
	res := msg.BuildResponse(zones, dnsCache, blocklist)
	conn.WriteToUDP(res, remoteAddr)
}

func main() {
	cmd.Execute()
	loadZones()
	// loadBlocklist()
	blocklist["google.com."] = true
	server := NewServer(
		"127.0.0.1:53153",
	)
	server.Run()
}
