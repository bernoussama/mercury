package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	// Resolve the string address to a UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53153")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Dial to the address with UDP
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for i := range 10 {
		go sendQuery(conn, "Hello UDP Server\n", i)
	}
}

func sendQuery(conn *net.UDPConn, query string, i int) {
	// Send a message to the server
	fmt.Println("send...", i)
	_, err := conn.Write([]byte(query))
	fmt.Println("send...")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Read from the connection untill a new line is send
	data, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the data read from the connection to the terminal
	fmt.Print("> ", string(data))
}
