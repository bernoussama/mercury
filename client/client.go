package client

import (
	"log"
	"net"
	"sync"

	"golang.org/x/exp/rand"
)

const (
	BUFFER_SIZE = 512
)

func main() {
	go runConcurrentClientTests(10)
	select {}
}

func runConcurrentClientTests(numClients int) {
	const numRequestsPerClient = 5

	var wg sync.WaitGroup
	wg.Add(numClients)

	for i := 0; i < numClients; i++ {
		go func(clientID int) {
			defer wg.Done()
			for j := 0; j < numRequestsPerClient; j++ {
				sendTestQuery(clientID, j)
			}
		}(i)
	}

	wg.Wait()
}

func sendTestQuery(clientID, requestID int) {
	conn, err := net.Dial("udp", "127.0.0.1:53153")
	if err != nil {
		log.Printf("Client %d: Failed to connect: %v\n", clientID, err)
		return
	}
	defer conn.Close()

	query := buildTestQuery("example.com")
	_, err = conn.Write(query)
	if err != nil {
		log.Printf("Client %d: Failed to send query %d: %v\n", clientID, requestID, err)
		return
	}

	buffer := make([]byte, BUFFER_SIZE)
	_, err = conn.Read(buffer)
	if err != nil {
		log.Printf("Client %d: Failed to read response for query %d: %v\n", clientID, requestID, err)
		return
	}

	log.Printf("Client %d: Received response for query %d\n", clientID, requestID)
}

func buildTestQuery(domain string) []byte {
	header := Header{
		ID:      uint16(rand.Intn(65535)),
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

	question := Question{
		DomainName: domain,
		QType:      TypeA,
		QClass:     1,
	}

	msg := Message{
		Header:   header,
		Question: question,
	}

	return msg.Encode()
}
