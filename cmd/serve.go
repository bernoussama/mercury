/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/bernoussama/mercury/dns"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
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

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "serve a dns queries",
	Long: `Mercury is a lightweight DNS server that provides DNS resolution for a given set of zones.
This server is designed to be used as as recursive resolver and a sinkhole, blocking unwanted DNS requests.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("serve called")
		address := "127.0.0.1:53153"
		loadZones()
		// loadBlocklist()
		blocklist["google.com."] = true
		server := NewServer(
			address,
		)
		server.Run()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
