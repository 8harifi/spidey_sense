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
	fmt.Println(strData)
	strDataLines := strings.Split(strData, "\r\n")
	method := strings.Split(strDataLines[0], " ")[0]
	// hostName := strings.Split(strDataLines[1], " ")[1]
	hostName := strings.Split(strDataLines[0], " ")[1]
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
	log.Println("[+] Handling HTTPS request for:", dr.url)

	// ✅ Inform the browser that the connection is established
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Fatal("[ERROR] Failed to send connection established response:", err)
	}

	// 🔐 Generate and use a fake certificate for MITM interception
	cert, err := GenerateCertificate(ca.certificate, ca.privateKey, dr.host)
	if err != nil {
		log.Fatal("[ERROR] Failed to generate certificate:", err)
	}

	tlsCert, err := tls.X509KeyPair(cert.certPem.Bytes(), cert.privateKeyPem.Bytes())
	if err != nil {
		log.Fatal("[ERROR] Failed to create X509 Key Pair:", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// 🔒 Upgrade client connection (browser) to TLS
	tlsConn := tls.Server(conn, tlsConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		log.Fatal("[ERROR] TLS handshake failed:", err)
	}

	log.Println("[+] TLS handshake successful for:", dr.url)

	// 🌍 Connect to the real target website
	targetConn, err := net.Dial("tcp", dr.url)
	if err != nil {
		log.Fatal("[ERROR] Failed to connect to target site:", err)
	}
	defer targetConn.Close()

	log.Println("[+] Connected to target site:", dr.url)

	// 🔁 **Bidirectional Communication (Full Duplex Proxying)**
	go func() {
		_, err := io.Copy(targetConn, tlsConn) // Browser > Proxy > Target
		if err != nil {
			log.Println("[ERROR] Failed to forward client data:", err)
		} else {
			log.Println("[+] successfully sent data from server to client throug proxy")
		}
	}()

	_, err = io.Copy(tlsConn, targetConn) // Target > Proxy > Browser
	if err != nil {
		log.Println("[ERROR] Failed to forward target response:", err)
	} else {
		log.Println("[+] successfully sent data from client to server throug proxy")
	}

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
