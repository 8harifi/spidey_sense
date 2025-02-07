package proxy

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type DownstreamRequest struct {
	method string
	host   string
	port   string
	url    string
}

func downstreamRequestParser(data []byte) *DownstreamRequest {
	strData := string(data)
	strDataLines := strings.Split(strData, "\r\n")
	method := strings.Split(strDataLines[0], " ")[0]
	if method == "CONNECT" {
		return nil
	}
	hostName := strings.Split(strDataLines[1], " ")[1]
	var port string
	if strings.Contains(hostName, ":") {
		port = strings.Split(hostName, ":")[1]
		hostName = strings.Split(hostName, ":")[0]
	} else {
		port = "80"
	}
	dr := DownstreamRequest{
		method: method,
		host:   hostName,
		port:   port,
		url:    hostName + ":" + port,
	}
	return &dr
}

func handleConnection(conn net.Conn) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	dr := downstreamRequestParser(buffer[:n])

	fmt.Println("[+] got request for " + dr.url)

	dial, err := net.Dial("tcp", dr.url)
	if err != nil {
		log.Fatal(err)
	}

	_, err = dial.Write(buffer[:n])
	if err != nil {
		log.Fatal(err)
	}

	hostResponseBuffer := make([]byte, 1024)
	_, err = dial.Read(hostResponseBuffer)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(hostResponseBuffer)
	if err != nil {
		log.Fatal(err)
	}

}

func StartProxy() {
	listen, err := net.Listen("tcp", ":8080")
	if err != nil {
		return
	}
	defer func(listen net.Listener) {
		err := listen.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(listen)
	fmt.Println("[+] Proxy Server Listening on :8080")
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn)
	}
}
