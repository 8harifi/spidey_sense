package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

type Certificate struct {
	certificate   *x509.Certificate
	privateKey    *rsa.PrivateKey
	certPem       bytes.Buffer
	privateKeyPem bytes.Buffer
}

func LoadOrCreateCACertificate() (*Certificate, error) {
	pemFileName := "rootCA.pem"
	keyFileName := "rootCA.key"

	if _, err := os.Stat(pemFileName); errors.Is(err, os.ErrNotExist) {
		fmt.Println("[DEBUG] rootCA.pem not found, generating a new CA")
		certificate, err := GenerateRootCA()
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(pemFileName, certificate.certPem.Bytes(), 0644)
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(keyFileName, certificate.privateKeyPem.Bytes(), 0600)
		if err != nil {
			return nil, err
		}

		fmt.Println("[DEBUG] New CA certificate and key generated")
		return certificate, nil
	}

	fmt.Println("[DEBUG] Loading existing CA certificate and key")

	certPemFileContent, err := os.ReadFile(pemFileName)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPemFileContent)
	if certBlock == nil {
		fmt.Println("[ERROR] Failed to decode PEM block (certificate)")
		return nil, errors.New("failed to decode PEM block (certificate)")
	}

	certificate := &Certificate{}
	certificate.certificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("[ERROR] Failed to parse CA certificate:", err)
		return nil, err
	}

	privateKeyPem, err := os.ReadFile(keyFileName)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyPem)
	if privateKeyBlock == nil {
		fmt.Println("[ERROR] Failed to decode PEM block (private key)")
		return nil, errors.New("failed to decode PEM block (private key)")
	}

	certificate.privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		fmt.Println("[ERROR] Failed to parse CA private key:", err)
		return nil, err
	}

	// Ensure the buffers are properly initialized
	certificate.privateKeyPem = *bytes.NewBuffer(privateKeyPem)
	certificate.certPem = *bytes.NewBuffer(certPemFileContent)

	// **Debugging Output**
	fmt.Println("[DEBUG] Successfully loaded CA certificate and private key")
	fmt.Println("[DEBUG] CA Certificate Subject:", certificate.certificate.Subject.CommonName)
	fmt.Println("[DEBUG] CA Key Size:", certificate.privateKey.N.BitLen())

	return certificate, nil
}

func GenerateCertificate(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey, host string) (*Certificate, error) {
	if ca == nil {
		log.Fatal("[ERROR] CA certificate is nil in GenerateCertificate!")
	}
	if caPrivateKey == nil {
		log.Fatal("[ERROR] CA private key is nil in GenerateCertificate!")
	}
	if ca.PublicKey == nil {
		log.Fatal("[ERROR] CA public key is nil in GenerateCertificate!")
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), // Unique serial number
		Subject: pkix.Name{
			CommonName:    host, // 🌍 Set CN to the target hostname
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // Valid for 1 year
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,

		// 🏆 **Dynamically set SAN to match the intercepted website**
		DNSNames: []string{host}, // The hostname of the intercepted request
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatal("[ERROR] Failed to create certificate:", err)
	}

	certPem := new(bytes.Buffer)
	err = pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	certPrivKeyPem := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	})
	if err != nil {
		return nil, err
	}

	return &Certificate{
		certificate:   cert,
		privateKey:    certPrivateKey,
		certPem:       *certPem,
		privateKeyPem: *certPrivKeyPem,
	}, nil
}

func GenerateRootCA() (*Certificate, error) {
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:    "My Custom CA",
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		PublicKey:             &caPrivateKey.PublicKey, // **Ensure PublicKey is set**
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatal("[ERROR] Failed to create root CA certificate:", err)
	}

	caPem := new(bytes.Buffer)
	err = pem.Encode(caPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}

	caPrivKeyPem := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})
	if err != nil {
		return nil, err
	}

	return &Certificate{
		certificate:   ca,
		privateKey:    caPrivateKey,
		certPem:       *caPem,
		privateKeyPem: *caPrivKeyPem,
	}, nil
}
