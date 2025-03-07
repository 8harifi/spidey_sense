package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

type DownstreamRequest struct {
	method string
	host   string
	port   string
	url    string
	bytes  []byte
}

func downstreamRequestParser(data []byte) *DownstreamRequest {
	strData := string(data)
	strDataLines := strings.Split(strData, "\r\n")
	method := strings.Split(strDataLines[0], " ")[0]
	hostName := strings.Split(strDataLines[1], " ")[1]
	var port string
	if strings.Contains(hostName, ":") {
		port = strings.Split(hostName, ":")[1]
		hostName = strings.Split(hostName, ":")[0]
	} else if method == "CONNECT" {
		port = "443"
	} else {
		port = "80"
	}
	dr := DownstreamRequest{
		method: method,
		host:   hostName,
		port:   port,
		url:    hostName + ":" + port,
		bytes:  data,
	}
	return &dr
}

func handleHTTPConnection(conn net.Conn, dr *DownstreamRequest) {
	fmt.Println("[+] got http request for " + dr.url)

	dial, err := net.Dial("tcp", dr.url)
	if err != nil {
		log.Fatal(err)
	}

	_, err = dial.Write(dr.bytes)
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

func handleHTTPSConnection(conn net.Conn, dr *DownstreamRequest, ca Certificate) {
	fmt.Println("[+] got https request for " + dr.url)

	_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Fatal(err)
	}

	cert, err := GenerateCertificate(ca.certificate, ca.privateKey)
	if err != nil {
		log.Fatal(err)
	}

	tlsCert, err := tls.X509KeyPair(cert.certPem.Bytes(), cert.privateKeyPem.Bytes())

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsConn := tls.Server(conn, tlsConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("[+] TLS handshake to the client successful for", dr.url)

	targetConn, err := net.Dial("tcp", dr.url)
	if err != nil {
		log.Fatal(err)
	}
	defer targetConn.Close()
	fmt.Println(1)

	go func() {
		_, _ = io.Copy(targetConn, tlsConn)
	}()

	_, _ = io.Copy(tlsConn, targetConn)
}

func StartProxy() {
	listen, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	ca, err := LoadOrCreateCACertificate()
	if err != nil {
		log.Fatal(err)
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

		buffer := make([]byte, 1024)

		n, err := conn.Read(buffer)
		if err != nil {
			log.Fatal(err)
		}

		dr := downstreamRequestParser(buffer[:n])

		if dr.method == "CONNECT" {
			go handleHTTPSConnection(conn, dr, *ca)
		} else {
			go handleHTTPConnection(conn, dr)
		}
	}
}
