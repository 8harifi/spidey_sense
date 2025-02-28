package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
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
		// The file does not exist, generate a new one
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

		return certificate, nil
	}

	// The file exists, load it
	certPemFileContent, err := os.ReadFile(pemFileName)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPemFileContent)
	if certBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Allocate memory for certificate struct before assigning fields
	certificate := &Certificate{}

	certificate.certificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	privateKeyPem, err := os.ReadFile(keyFileName)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyPem)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to decode PEM block (private key)")
	}

	certificate.privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Ensure the buffers are properly initialized
	certificate.privateKeyPem = *bytes.NewBuffer(privateKeyPem)
	certificate.certPem = *bytes.NewBuffer(certPemFileContent)

	return certificate, nil
}

func GenerateCertificate(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
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
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
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
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
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
